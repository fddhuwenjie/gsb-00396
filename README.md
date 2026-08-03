# CertScope

基于 React + TypeScript + Vite 的 X.509 证书 / CSR / CRL 解析与链验证工具，全部解析在浏览器中完成（源码见 `src/utils/`）。

## 常用命令

```bash
npm install       # 安装依赖
npm run dev       # 启动开发服务器
npm test          # 运行 Vitest 单元测试（全新安装后可直接运行）
npm run check     # TypeScript 类型检查
npm run build     # 生产构建（含类型检查）
```

## 测试

测试使用 [Vitest](https://vitest.dev/)，配置在 `vitest.config.ts`，测试文件位于 `tests/`。
测试通过 `import.meta.url` 定位夹具并直接导入 `src/utils/` 下的解析源码，与浏览器应用共用同一份实现，不依赖 Node 原生执行 `.ts`、手工 loader 或特定工作目录。

### 夹具（tests/fixtures/）

夹具为固定的 PEM 文件，**不包含任何私钥**，覆盖根证书、叶证书和一份 CSR：

| 文件 | 内容 | 关键字段 |
| --- | --- | --- |
| `root-cert.pem` | 自签名根 CA（RSA-2048，CA:TRUE） | CN=Test Root CA，2026-06-12 ~ 2036-06-09 |
| `leaf-cert.pem` | 由中间 CA 签发的叶证书（RSA-2048，CA:FALSE） | CN=test.example.com，2026-06-12 ~ 2027-06-12，含 SAN/KU/EKU |
| `leaf-csr.pem` | 与叶证书对应的 CSR（sha256WithRSAEncryption） | CN=test.example.com |
| `expired-cert.pem` | 已过期自签名证书（RSA-2048，无扩展） | CN=expired.example.com，2020-01-01 ~ 2021-01-01，serial=1000(hex) |

夹具来源：

- 前三者拷贝自仓库 `test-certs/` 目录，该目录是使用 OpenSSL 在本地生成的测试专用证书链（自签名根 → 中间 CA → 叶证书），例如：

```bash
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=TestOrg/OU=TestUnit/CN=Test Root CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -keyout root-key.pem -out root-cert.pem

openssl req -new -newkey rsa:2048 -nodes \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=TestOrg/OU=TestUnit/CN=test.example.com" \
  -keyout leaf-key.pem -out leaf-csr.pem

openssl x509 -req -in leaf-csr.pem -CA intermediate-cert.pem -CAkey intermediate-key.pem \
  -days 365 -extfile leaf-ext.cnf -out leaf-cert.pem
```

- `expired-cert.pem` 使用 `openssl ca -selfsign` 配合 `-startdate 20200101000000Z -enddate 20210101000000Z` 回填日期生成（临时密钥用后即删，未入库）：

```bash
openssl req -new -newkey rsa:2048 -nodes \
  -subj "/C=CN/ST=Beijing/O=TestOrg/OU=TestUnit/CN=expired.example.com" \
  -keyout key.pem -out req.csr
openssl ca -selfsign -config openssl.cnf -in req.csr -out expired-cert.pem \
  -startdate 20200101000000Z -enddate 20210101000000Z -batch
```

测试中过期证书关键字段（主题、有效期、序列号等）的预期值均以生成时的 OpenSSL 输出为准固定，不取自待测解析器。重新生成证书后，对应的私钥文件不应提交到仓库。

## 页面

- `/`：主页（X.509 字段、ASN.1 树、链验证、OpenSSL 输出、生成 CSR、CRL 解析）
- `/certificate`：证书详情页，展示序列号、主题、颁发者、有效期、公钥算法、签名算法和扩展字段；解析失败显示明确错误，页面渲染异常由错误边界兜底，不会导致整个页面崩溃
  - 有效期评估：可选择评估时间，通过纯函数 `evaluateValidity(validity, at)` 判断"尚未生效 / 当前有效 / 已经过期"，并显示距离生效或过期的天数（向上取整；有效期两端为闭区间）。相同证书与评估时间必得相同结果，且只取决于绝对时刻，与时区无关
  - 最后一次评估时间与结果保存在 localStorage（`certscope:lastValidityEvaluation`），页面刷新后仍可查看

### 测试覆盖

- `tests/asn1-length.test.ts`：DER 长度解析（短形式、1/2/3 字节长形式、不定长拒绝、截断拒绝）
- `tests/x509.test.ts`：证书主题、颁发者、有效期、Basic Constraints、Key Usage、SAN；有效期判断通过 `isWithinValidity(validity, at)` 传入显式时间，不依赖当天日期
- `tests/csr.test.ts`：CSR 版本、主题、签名算法、公钥算法与长度
- `tests/expired-cert.test.ts`：过期证书的主题、颁发者、序列号、有效期（预期值固定自 OpenSSL 输出），并用显式时间验证已过期
- `tests/corrupted-input.test.ts`：截断 DER、垃圾字节、非证书 SEQUENCE、非法 Base64 等损坏输入的报错，以及 store 解析失败时的错误状态与恢复
- `tests/validity.test.ts`：有效期评估三态（尚未生效 / 当前有效 / 已经过期）与天数计算、有效期端点闭区间边界、确定性（相同输入必得相同结果）、时区边界（同一时刻不同时区表示结果一致）

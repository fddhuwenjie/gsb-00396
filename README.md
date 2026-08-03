# CertScope

浏览器内 X.509 证书解析与验证工具。基于 Web Crypto API，自实现 ASN.1 / DER 解析，纯本地运行，数据不上传。

## 页面

- `/` 主工作台：X.509 字段、ASN.1 树、链验证、OpenSSL 输出、CSR 生成、CRL 解析。
- `/certificate` 证书详情页：粘贴一份 PEM 证书即可查看序列号、主题、颁发者、有效期、公钥算法、签名算法和常用扩展（Basic Constraints、Key Usage、EKU、SAN、SKI/AKI）。可通过“评估时间 (UTC)”选择器指定任意评估时刻，页面明确显示**尚未生效 / 当前有效 / 已经过期**，并展示距离生效或过期的天数。解析失败时显示明确错误并由错误边界兜底，不会让整个页面崩溃。最后一次输入的证书和评估时间会保存在 `localStorage`，刷新页面后自动恢复。

## 命令

| 命令 | 说明 |
| --- | --- |
| `npm run dev` | 启动 Vite 开发服务器 |
| `npm run build` | 类型检查并生产构建（输出到 `dist/`） |
| `npm run check` | TypeScript 类型检查（不产出文件） |
| `npm run lint` | 运行 ESLint |
| `npm test` | 运行 Vitest 测试（单次运行，CI 友好） |
| `npm run test:watch` | 以监听模式运行 Vitest |
| `npm run preview` | 本地预览生产构建 |

## 测试

测试使用 [Vitest](https://vitest.dev/)，配置见 [vitest.config.ts](vitest.config.ts)。

- `npm test` 在全新 `npm install` 后即可直接运行，不依赖 Node 原生执行 `.ts`、手工 loader 或特定工作目录。
- 测试通过 Vite 的转换管线直接导入 `src/utils/` 下的 TypeScript 源码，与浏览器应用共用同一份解析实现（例如 `parseX509`、`parseCSR`、`parseASN1`、`validateChain`）。
- 验证时间通过 `validateChain(chain, crls, now)` 的第三个参数显式传入，测试不依赖当天日期。

测试文件位于 [tests/](tests/)：

- [asn1.test.ts](tests/asn1.test.ts)：ASN.1 长度编码（短形式、长形式、不定长拒绝）、PEM 解析、结构解析。
- [x509.test.ts](tests/x509.test.ts)：证书版本、序列号、主题、颁发者、有效期、公钥、基本约束、SAN、Key Usage、EKU、SKI/AKI。
- [csr.test.ts](tests/csr.test.ts)：PKCS#10 CSR 的版本、主题、公钥、签名算法与签名值。
- [chain.test.ts](tests/chain.test.ts)：证书链构建与在固定时间点的签名/有效期验证。
- [certificate-detail.test.ts](tests/certificate-detail.test.ts)：证书详情页解析辅助函数，覆盖正常证书、过期证书、空输入、非 PEM、损坏 DER 与非 CERTIFICATE 的 PEM 块；有效期三状态、天数计算、评估时间解析与时区边界。
- [CertificateDetail.test.tsx](tests/CertificateDetail.test.tsx)：详情页组件（jsdom），验证正常/过期/损坏输入的渲染、错误提示与不崩溃；评估时间选择驱动的三状态与天数展示；以及 `localStorage` 持久化与刷新恢复。

## 测试夹具

固定夹具位于 [tests/fixtures/](tests/fixtures/)，均为 PEM 文本，**只包含证书或 CSR 等公开材料，不含任何私钥**（已用 `grep PRIVATE KEY` 校验）。

| 文件 | 类型 | 主题 / CN | 颁发者 | 有效期 (UTC) | 说明 |
| --- | --- | --- | --- | --- | --- |
| `root-cert.pem` | 自签名根 CA | Test Root CA | Test Root CA | 2026-06-12 08:24:17 – 2036-06-09 08:24:17 | RSA 2048，Basic Constraints CA:TRUE（critical） |
| `intermediate-cert.pem` | 中间 CA | Test Intermediate CA | Test Root CA | 2026-06-12 08:25:08 – 2031-06-11 08:25:08 | RSA 2048，pathlen:0 |
| `leaf-cert.pem` | 叶子证书 | test.example.com | Test Intermediate CA | 2026-06-12 08:25:26 – 2027-06-12 08:25:26 | RSA 2048，含 SAN（DNS / IP / email / URI） |
| `leaf-csr.pem` | PKCS#10 CSR | test.example.com | — | — | RSA 2048，sha256WithRSAEncryption，无属性 |
| `expired-cert.pem` | 自签名叶子证书（已过期） | expired.example.com | expired.example.com | 2020-01-01 00:00:00 – 2021-01-01 00:00:00 | RSA 2048，CA:FALSE，含 SAN；序列号 `0BADBEEFCAFEBABEDEADBEEFCAFEBABE` |
| `corrupted-cert.pem` | 损坏的 PEM（有效 PEM 头尾，但 base64 解码后不是合法 DER） | — | — | — | 用于验证解析失败路径 |

### 夹具来源与复现

这些夹具是为测试套件使用 OpenSSL 在本地生成的测试证书，复制自仓库中的 `test-certs/` 目录，不来自任何真实机构或公开日志。其字段可通过以下命令复核：

```bash
openssl x509 -in tests/fixtures/root-cert.pem -noout -subject -issuer -dates -serial
openssl x509 -in tests/fixtures/leaf-cert.pem -noout -subject -issuer -dates -ext subjectAltName
openssl x509 -in tests/fixtures/expired-cert.pem -noout -subject -issuer -dates -serial -ext basicConstraints,subjectAltName
openssl req  -in tests/fixtures/leaf-csr.pem  -noout -subject -text
```

`expired-cert.pem` 使用 OpenSSL 3 的 `-not_before 20200101000000Z -not_after 20210101000000Z` 生成，确保其在任意当前时间都已过期；`corrupted-cert.pem` 的 base64 解码为非 DER 的随机字节，用于覆盖解析失败路径。

所有证书主题字段均为 `C=CN, ST=Beijing, L=Beijing, O=TestOrg, OU=TestUnit`，仅用于本地解析与链验证测试。

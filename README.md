# CertScope

浏览器内 X.509 证书解析与验证工具。基于 Web Crypto API，使用自实现的 ASN.1 DER 解析器，所有数据均在本地处理，不上传到任何服务器。

## 功能

- X.509 证书字段、ASN.1 树、证书链验证、OpenSSL 风格输出、CSR 生成与 CRL 解析（首页工作台）。
- 独立的[证书详情页](src/pages/CertificateDetail.tsx)（路由 `/certificate`）：粘贴 PEM 即可查看序列号、主题、颁发者、有效期、公钥与签名算法及常用扩展，并提供**有效期检查**。
- 有效期检查允许用户自行选择评估时间（UTC），页面明确显示「尚未生效 / 当前有效 / 已过期」三种状态，以及距离生效或过期的天数。结果由纯函数 [evaluateValidity](src/utils/cert-detail.ts) 根据证书的 `notBefore`/`notAfter` 与评估时间计算，**相同输入和评估时间必定得到相同结果**，不读取系统当天日期。天数按 UTC 日历日计算，因此不受浏览器本地时区影响。
- 解析失败时在内容区显示明确的错误信息，外层 [ErrorBoundary](src/components/ErrorBoundary.tsx) 兜底任何渲染异常，整个页面不会崩溃。
- 证书详情页会把最后一次粘贴的 PEM 和评估时间保存到浏览器 `localStorage`，刷新页面后自动恢复，因此最后一次评估结果也会随之保留。

## 开发命令

```bash
npm install        # 安装依赖
npm run dev        # 启动 Vite 开发服务器
npm run build      # 类型检查 + 生产构建（输出到 dist/）
npm run preview    # 本地预览生产构建
npm run check      # 仅运行 TypeScript 类型检查（tsc -b --noEmit）
npm run lint       # 运行 ESLint
npm test           # 运行一次 Vitest 测试套件
npm run test:watch # 以 watch 模式运行 Vitest
```

`npm test` 在全新 `npm install` 之后可直接运行，不依赖 Node 原生执行 `.ts`、手工 loader 或特定工作目录。测试与浏览器应用导入同一份解析源码（`src/utils/*`），由 Vitest 通过 Vite 的模块管线进行转换。

## 测试

测试使用 [Vitest](https://vitest.dev/)，配置见 [vitest.config.ts](vitest.config.ts)。测试文件与被测源码放在同一目录，命名为 `*.test.ts`：

- [src/utils/asn1.test.ts](src/utils/asn1.test.ts) — ASN.1 DER 长度编码（短形式、长形式、非法 indefinite 长度等）、PEM 解析与顶层 SEQUENCE。
- [src/utils/x509.test.ts](src/utils/x509.test.ts) — X.509 版本、序列号、签名算法、颁发者/主题 DN、有效期、公钥信息、扩展（SAN / EKU / Basic Constraints / Key Usage）。
- [src/utils/csr.test.ts](src/utils/csr.test.ts) — PKCS#10 CSR 版本、主题 DN、公钥、签名算法、扩展请求属性与 SAN。
- [src/utils/chain.test.ts](src/utils/chain.test.ts) — 证书链构建、签名验证、以及基于显式参考时间的有效期判断。
- [src/utils/cert-detail.test.ts](src/utils/cert-detail.test.ts) — 证书详情页使用的安全解析逻辑：正常证书、过期证书、空输入、非证书文本、错误 PEM 标签、被损坏的 PEM 以及非法 Base64/DER；以及纯函数 `evaluateValidity` 的三种状态、精确边界（notBefore/notAfter 前后一毫秒）、UTC 日历日天数与时区无关性、重复调用确定性。关键字段（序列号、颁发者/主题、有效期、公钥位数、SAN 等）的预期值来自 `openssl x509` 输出，而非由待测解析器自行生成。

### 固定参考时间

有效期相关的断言不会读取系统当天日期。`validateChain` 接受一个可选的 `verifyAt: Date` 参数（默认为 `new Date()`），证书详情页的状态判断函数 `getValidityState(fields, now)` 同样把时间作为参数传入，测试用固定的 UTC 时间调用它，因此无论何时运行结果都一致。

## 测试夹具

固定夹具位于 [test/fixtures/](test/fixtures/)，**只包含 PEM 编码的证书和 CSR，不包含任何私钥**。私钥在生成后立即删除，且 `.gitignore` 会忽略 `*-key.pem`。

| 文件 | 说明 | 有效期 |
| --- | --- | --- |
| `root-cert.pem` | 自签名 RSA-2048 根证书，Subject/Issuer 为 `CN=CertScope Test Root CA, OU=Testing, O=CertScope Test, L=Beijing, ST=Beijing, C=CN` | 2026-08-03 05:57:23Z → 2036-07-31 05:57:23Z |
| `leaf-cert.pem` | 由上述根证书签发的 RSA-2048 叶证书，Subject 为 `CN=leaf.example.com, OU=Web, O=CertScope Test, ...`，SAN 包含 `leaf.example.com`、`www.leaf.example.com`、`192.0.2.10` | 2026-08-03 05:57:23Z → 2027-08-03 05:57:23Z |
| `leaf-csr.pem` | 与叶证书公钥对应的 PKCS#10 CSR，使用相同 Subject 与 SAN 扩展请求 | — |
| `expired-cert.pem` | 自签名 RSA-2048 证书，Subject 为 `CN=expired.example.com, OU=Legacy, O=CertScope Test, L=Shanghai, ST=Shanghai, C=CN`，序列号 `0x3001`，用于测试过期状态显示（相对于固定参考时间 2026-08-03 已过期） | 2020-01-01 00:00:00Z → 2021-01-01 00:00:00Z |

### 夹具来源与复现方式

夹具为专门为本仓库生成的测试数据，使用系统自带的 OpenSSL 3.x 在本地生成，不来自任何真实证书。可通过以下命令复现（在仓库根目录执行）：

```bash
mkdir -p test/fixtures && cd test/fixtures

# 根证书（自签名，有效期 10 年）
openssl genrsa -out root.key.pem 2048
openssl req -x509 -new -nodes -key root.key.pem -sha256 -days 3650 \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=CertScope Test/OU=Testing/CN=CertScope Test Root CA" \
  -set_serial 0x1000 \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out root-cert.pem

# 叶证书密钥与 CSR
openssl genrsa -out leaf.key.pem 2048
openssl req -new -key leaf.key.pem \
  -subj "/C=CN/ST=Beijing/L=Beijing/O=CertScope Test/OU=Web/CN=leaf.example.com" \
  -addext "subjectAltName=DNS:leaf.example.com,DNS:www.leaf.example.com,IP:192.0.2.10" \
  -addext "extendedKeyUsage=serverAuth,clientAuth" \
  -addext "basicConstraints=CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -out leaf-csr.pem

# 用根证书签发叶证书（有效期 1 年）
openssl x509 -req -in leaf-csr.pem -CA root-cert.pem -CAkey root.key.pem -CAcreateserial \
  -days 365 -sha256 -set_serial 0x2001 \
  -extfile <(printf "subjectAltName=DNS:leaf.example.com,DNS:www.leaf.example.com,IP:192.0.2.10\nextendedKeyUsage=serverAuth,clientAuth\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer") \
  -out leaf-cert.pem

# 删除私钥与序列号文件，保证夹具中不含私钥
rm -f root.key.pem leaf.key.pem root-cert.srl

# 过期证书（自签名，使用固定的过去时间窗口，用于测试过期状态）
openssl genrsa -out expired.key.pem 2048
openssl req -new -key expired.key.pem \
  -subj "/C=CN/ST=Shanghai/L=Shanghai/O=CertScope Test/OU=Legacy/CN=expired.example.com" \
  -out expired-csr.pem
openssl x509 -req -in expired-csr.pem -signkey expired.key.pem \
  -sha256 -set_serial 0x3001 \
  -not_before 20200101000000Z -not_after 20210101000000Z \
  -extfile <(printf "subjectAltName=DNS:expired.example.com\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nsubjectKeyIdentifier=hash") \
  -out expired-cert.pem
rm -f expired.key.pem expired-csr.pem
```

> 注意：重新生成会改变证书中的公钥、签名和 `notBefore/notAfter` 时间戳，测试中对这些字段的硬编码断言需要同步更新。

## 项目结构

```
src/
  utils/
    asn1.ts      # ASN.1 DER 解析器（tag/length/OID/string 等）
    x509.ts      # X.509 证书字段解析
    csr.ts       # PKCS#10 CSR 生成与解析
    chain.ts     # 证书链构建与验证（含 verifyAt 参考时间参数）
    verify.ts    # 基于 Web Crypto 的签名验证
    crl.ts       # CRL 解析
    oids.ts      # OID 名称映射
    openssl-format.ts
    cert-detail.ts # 证书详情页安全解析（不抛异常，返回 ok/error）
  components/    # React UI 组件
  pages/         # 页面：Home（工作台）、CertificateDetail（/certificate 证书详情）
test/
  fixtures/      # 固定证书/CSR 夹具（无私钥）
```

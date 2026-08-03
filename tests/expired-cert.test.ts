import { describe, expect, it } from 'vitest';
import { isWithinValidity, parseX509 } from '../src/utils/x509';
import { loadFixtureDer } from './helpers';

// 预期值来自夹具生成时的 OpenSSL 输出：
//   subject= /CN=expired.example.com/C=CN/ST=Beijing/O=TestOrg/OU=TestUnit
//   issuer=  /CN=expired.example.com/C=CN/ST=Beijing/O=TestOrg/OU=TestUnit
//   notBefore=Jan  1 00:00:00 2020 GMT
//   notAfter=Jan  1 00:00:00 2021 GMT
//   serial=1000（十六进制）
//   Signature Algorithm: sha256WithRSAEncryption，RSA Public-Key: (2048 bit)
describe('expired certificate fixture', () => {
  const { fields } = parseX509(loadFixtureDer('expired-cert.pem'));

  it('parses subject', () => {
    expect(fields.subject['2.5.4.3']).toEqual(['expired.example.com']);
    expect(fields.subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(fields.subject['2.5.4.11']).toEqual(['TestUnit']);
    expect(fields.subject['2.5.4.6']).toEqual(['CN']);
  });

  it('parses issuer (self-signed: identical to subject)', () => {
    expect(fields.issuer).toEqual(fields.subject);
  });

  it('parses serial number from OpenSSL-pinned value (serial=1000 hex)', () => {
    expect(fields.serialNumber).toBe('4096 (0x1000)');
  });

  it('parses validity period pinned by OpenSSL', () => {
    expect(fields.validity.notBefore).toEqual(new Date(Date.UTC(2020, 0, 1, 0, 0, 0)));
    expect(fields.validity.notAfter).toEqual(new Date(Date.UTC(2021, 0, 1, 0, 0, 0)));
  });

  it('parses signature and public key algorithms', () => {
    expect(fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(fields.subjectPublicKeyInfo.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(fields.subjectPublicKeyInfo.keySize).toBe(2048);
  });

  it('has no extensions', () => {
    expect(fields.extensions).toEqual([]);
  });

  it('is expired when evaluated at an explicit later time', () => {
    const { validity } = fields;
    expect(isWithinValidity(validity, new Date(Date.UTC(2020, 5, 1)))).toBe(true);
    // 证书 2021-01-01 到期，以下固定时间点已过期（不依赖测试运行当天）
    expect(isWithinValidity(validity, new Date(Date.UTC(2026, 0, 1)))).toBe(false);
    // 生效之前的时间点同样无效
    expect(isWithinValidity(validity, new Date(Date.UTC(2019, 0, 1)))).toBe(false);
  });
});

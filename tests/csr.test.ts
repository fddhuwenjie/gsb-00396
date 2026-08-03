import { describe, it, expect } from 'vitest';
import { parseCSRFromPEM } from '../src/utils/csr';
import { loadFixture } from './helpers';

describe('CSR (PKCS#10) parsing', () => {
  const csr = parseCSRFromPEM(loadFixture('leaf-csr.pem'));

  it('reports version 1', () => {
    expect(csr.fields.version).toBe(1);
  });

  it('parses the subject distinguished name', () => {
    const subject = csr.fields.subject;
    expect(subject['2.5.4.6']).toEqual(['CN']);
    expect(subject['2.5.4.8']).toEqual(['Beijing']);
    expect(subject['2.5.4.7']).toEqual(['Beijing']);
    expect(subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(subject['2.5.4.11']).toEqual(['TestUnit']);
    expect(subject['2.5.4.3']).toEqual(['test.example.com']);
    expect(csr.fields.subjectRaw).toContain('CN = test.example.com');
  });

  it('parses the RSA public key (2048 bit)', () => {
    expect(csr.fields.subjectPublicKeyInfo.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(csr.fields.subjectPublicKeyInfo.algorithm.name).toBe('rsaEncryption');
    expect(csr.fields.subjectPublicKeyInfo.keySize).toBe(2048);
    expect(csr.fields.subjectPublicKeyInfo.raw.length).toBeGreaterThan(0);
  });

  it('parses the signature algorithm', () => {
    expect(csr.fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(csr.fields.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
    expect(csr.signatureAlgorithm).toBe('1.2.840.113549.1.1.11');
  });

  it('exposes the raw signature and certificationRequestInfo', () => {
    expect(csr.signatureRaw).toBeInstanceOf(Uint8Array);
    expect(csr.signatureRaw.length).toBe(256);
    expect(csr.criRaw.length).toBeGreaterThan(0);
    expect(csr.criRaw[0]).toBe(0x30);
  });

  it('has no extension request / SAN attributes', () => {
    expect(csr.fields.san).toBeUndefined();
  });
});

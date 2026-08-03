import { describe, it, expect } from 'vitest';
import { parsePEM } from './asn1';
import { parseCSRFromPEM } from './csr';
import { loadFixture } from '../test/fixtures';

describe('CSR parsing', () => {
  const pem = loadFixture('leaf-csr.pem');
  const { fields } = parseCSRFromPEM(pem);

  it('reports PKCS#10 version 0', () => {
    expect(fields.version).toBe(0);
  });

  it('parses the subject distinguished name', () => {
    const subject = fields.subject;
    expect(subject['2.5.4.6']).toEqual(['CN']);
    expect(subject['2.5.4.8']).toEqual(['Beijing']);
    expect(subject['2.5.4.7']).toEqual(['Beijing']);
    expect(subject['2.5.4.10']).toEqual(['CertScope Test']);
    expect(subject['2.5.4.11']).toEqual(['Web']);
    expect(subject['2.5.4.3']).toEqual(['leaf.example.com']);
    expect(fields.subjectRaw).toContain('leaf.example.com');
  });

  it('parses the embedded RSA public key', () => {
    const spki = fields.subjectPublicKeyInfo;
    expect(spki.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(spki.algorithm.name).toBe('rsaEncryption');
    expect(spki.keySize).toBe(2048);
    expect(spki.raw.length).toBeGreaterThan(0);
    expect(spki.rsaExponent).toBe(65537n);
  });

  it('parses the requested signature algorithm', () => {
    expect(fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(fields.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
    expect(fields.signatureRaw.length).toBeGreaterThan(0);
  });

  it('parses the extension request attribute (PKCS#9 1.9.14)', () => {
    const extReq = fields.attributes.find(
      (a) => a.oid === '1.2.840.113549.1.9.14',
    );
    expect(extReq).toBeDefined();
    expect(extReq!.values.length).toBeGreaterThan(0);
  });

  it('parses the requested subject alternative names', () => {
    const san = fields.san!;
    expect(san).toBeDefined();
    const dns = san.filter((e) => e.type === 'DNS').map((e) => e.value);
    expect(dns).toEqual(['leaf.example.com', 'www.leaf.example.com']);
    const ips = san.filter((e) => e.type === 'IP').map((e) => e.value);
    expect(ips).toEqual(['192.0.2.10']);
  });

  it('produces a non-empty CertificationRequestInfo slice', () => {
    const { criRaw } = parseCSRFromPEM(pem);
    expect(criRaw.length).toBeGreaterThan(0);
    expect(criRaw[0]).toBe(0x30);
  });

  it('throws on input without a PEM block', () => {
    expect(() => parseCSRFromPEM('not a pem')).toThrow(/No valid PEM/);
  });
});

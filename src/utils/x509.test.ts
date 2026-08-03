import { describe, it, expect } from 'vitest';
import { parsePEM } from './asn1';
import { parseX509 } from './x509';
import { parseCertFromDER } from './chain';
import { loadFixture } from '../test/fixtures';

function parsePEMCert(name: string) {
  const pem = loadFixture(name);
  const { der } = parsePEM(pem)[0];
  return parseCertFromDER(der, pem);
}

describe('X.509 root certificate', () => {
  const cert = parsePEMCert('root-cert.pem');

  it('reports version 3', () => {
    expect(cert.fields.version).toBe(3);
  });

  it('has a non-empty serial number', () => {
    expect(cert.fields.serialNumber).toBeTruthy();
    expect(cert.fields.serialNumber).toContain('0x1000');
  });

  it('uses sha256WithRSAEncryption as signature algorithm', () => {
    expect(cert.fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(cert.fields.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
  });

  it('parses the issuer distinguished name', () => {
    const issuer = cert.fields.issuer;
    expect(issuer['2.5.4.6']).toEqual(['CN']);
    expect(issuer['2.5.4.8']).toEqual(['Beijing']);
    expect(issuer['2.5.4.7']).toEqual(['Beijing']);
    expect(issuer['2.5.4.10']).toEqual(['CertScope Test']);
    expect(issuer['2.5.4.11']).toEqual(['Testing']);
    expect(issuer['2.5.4.3']).toEqual(['CertScope Test Root CA']);
    expect(cert.fields.issuerRaw).toContain('CertScope Test Root CA');
  });

  it('is self-signed (subject equals issuer)', () => {
    expect(cert.fields.subject).toEqual(cert.fields.issuer);
    expect(cert.subjectRaw).toBe(cert.issuerRaw);
  });

  it('parses the validity window with exact UTC timestamps', () => {
    const { notBefore, notAfter } = cert.fields.validity;
    expect(notBefore.toISOString()).toBe('2026-08-03T05:57:23.000Z');
    expect(notAfter.toISOString()).toBe('2036-07-31T05:57:23.000Z');
  });

  it('recognizes an RSA public key and its size', () => {
    const spki = cert.fields.subjectPublicKeyInfo;
    expect(spki.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(spki.algorithm.name).toBe('rsaEncryption');
    expect(spki.keySize).toBe(2048);
    expect(spki.raw.length).toBeGreaterThan(0);
    expect(spki.rsaExponent).toBe(65537n);
  });

  it('parses basic constraints marking it as a CA', () => {
    expect(cert.fields.basicConstraints).toBeDefined();
    expect(cert.fields.basicConstraints!.ca).toBe(true);
  });

  it('parses key usage allowing cert and CRL signing', () => {
    expect(cert.fields.keyUsage).toContain('Certificate Sign');
    expect(cert.fields.keyUsage).toContain('CRL Sign');
  });
});

describe('X.509 leaf certificate', () => {
  const cert = parsePEMCert('leaf-cert.pem');

  it('is issued by the test root CA', () => {
    expect(cert.fields.issuer['2.5.4.3']).toEqual(['CertScope Test Root CA']);
    expect(cert.issuerRaw).toContain('CertScope Test Root CA');
  });

  it('parses the leaf subject', () => {
    const subject = cert.fields.subject;
    expect(subject['2.5.4.6']).toEqual(['CN']);
    expect(subject['2.5.4.10']).toEqual(['CertScope Test']);
    expect(subject['2.5.4.11']).toEqual(['Web']);
    expect(subject['2.5.4.3']).toEqual(['leaf.example.com']);
    expect(cert.subjectRaw).toContain('leaf.example.com');
  });

  it('parses the validity window with exact UTC timestamps', () => {
    const { notBefore, notAfter } = cert.fields.validity;
    expect(notBefore.toISOString()).toBe('2026-08-03T05:57:23.000Z');
    expect(notAfter.toISOString()).toBe('2027-08-03T05:57:23.000Z');
  });

  it('parses the subject alternative names', () => {
    const san = cert.fields.san!;
    expect(san).toBeDefined();
    const dns = san.filter((e) => e.type === 'DNS').map((e) => e.value);
    expect(dns).toEqual(['leaf.example.com', 'www.leaf.example.com']);
    const ips = san.filter((e) => e.type === 'IP').map((e) => e.value);
    expect(ips).toEqual(['192.0.2.10']);
  });

  it('parses extended key usage for server and client auth', () => {
    expect(cert.fields.extKeyUsage).toBeDefined();
    const joined = cert.fields.extKeyUsage!.join(' ');
    expect(joined).toContain('serverAuth');
    expect(joined).toContain('clientAuth');
  });

  it('is not a CA', () => {
    expect(cert.fields.basicConstraints!.ca).toBe(false);
  });
});

describe('X.509 validity evaluation with an explicit reference time', () => {
  const cert = parsePEMCert('leaf-cert.pem');
  const notBefore = cert.fields.validity.notBefore;
  const notAfter = cert.fields.validity.notAfter;

  function isWithinWindow(at: Date): boolean {
    return at >= notBefore && at <= notAfter;
  }

  it('is valid at a moment inside the window', () => {
    const during = new Date(Date.UTC(2027, 0, 1, 0, 0, 0));
    expect(isWithinWindow(during)).toBe(true);
  });

  it('is not yet valid before notBefore', () => {
    const before = new Date(notBefore.getTime() - 1000);
    expect(isWithinWindow(before)).toBe(false);
  });

  it('is expired after notAfter', () => {
    const after = new Date(notAfter.getTime() + 1000);
    expect(isWithinWindow(after)).toBe(false);
  });

  it('is valid exactly at notBefore and notAfter (inclusive)', () => {
    expect(isWithinWindow(notBefore)).toBe(true);
    expect(isWithinWindow(notAfter)).toBe(true);
  });
});

describe('parseX509 returns tbs and signature slices', () => {
  it('exposes non-empty tbsRaw and signatureRaw for the leaf cert', () => {
    const pem = loadFixture('leaf-cert.pem');
    const { der } = parsePEM(pem)[0];
    const { tbsRaw, signatureRaw, signatureAlgorithm } = parseX509(der);
    expect(tbsRaw.length).toBeGreaterThan(0);
    expect(signatureRaw.length).toBeGreaterThan(0);
    expect(signatureAlgorithm).toBe('1.2.840.113549.1.1.11');
  });
});

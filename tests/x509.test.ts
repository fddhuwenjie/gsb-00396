import { describe, it, expect } from 'vitest';
import { parseX509, formatDN } from '../src/utils/x509';
import { parsePEM } from '../src/utils/asn1';
import { loadFixture } from './helpers';

function parseFixture(name: string) {
  const pem = loadFixture(name);
  const der = parsePEM(pem)[0].der;
  return parseX509(der);
}

describe('X.509 root certificate', () => {
  const root = parseFixture('root-cert.pem');

  it('reports version 3', () => {
    expect(root.fields.version).toBe(3);
  });

  it('parses the serial number as hex', () => {
    expect(root.fields.serialNumber).toBe('0x3f68365e414c779d9b7286c7da55993f204abcec');
  });

  it('parses the signature algorithm as sha256WithRSAEncryption', () => {
    expect(root.fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(root.fields.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
  });

  it('parses the subject distinguished name', () => {
    const subject = root.fields.subject;
    expect(subject['2.5.4.6']).toEqual(['CN']);
    expect(subject['2.5.4.8']).toEqual(['Beijing']);
    expect(subject['2.5.4.7']).toEqual(['Beijing']);
    expect(subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(subject['2.5.4.11']).toEqual(['TestUnit']);
    expect(subject['2.5.4.3']).toEqual(['Test Root CA']);
  });

  it('has issuer identical to subject (self-signed)', () => {
    expect(root.fields.issuer).toEqual(root.fields.subject);
    expect(root.fields.issuerRaw).toBe(root.fields.subjectRaw);
  });

  it('renders a human-readable DN via formatDN', () => {
    expect(formatDN(root.fields.subject)).toContain('CN = Test Root CA');
    expect(formatDN(root.fields.subject)).toContain('C = CN');
    expect(formatDN(root.fields.subject)).toContain('O = TestOrg');
  });

  it('parses validity as fixed UTC dates independent of today', () => {
    expect(root.fields.validity.notBefore).toEqual(new Date(Date.UTC(2026, 5, 12, 8, 24, 17)));
    expect(root.fields.validity.notAfter).toEqual(new Date(Date.UTC(2036, 5, 9, 8, 24, 17)));
  });

  it('parses a 2048-bit RSA public key', () => {
    expect(root.fields.subjectPublicKeyInfo.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(root.fields.subjectPublicKeyInfo.keySize).toBe(2048);
    expect(root.fields.subjectPublicKeyInfo.raw.length).toBeGreaterThan(0);
  });

  it('parses basic constraints CA:TRUE as critical', () => {
    expect(root.fields.basicConstraints).toEqual({ ca: true });
    const bc = root.fields.extensions.find((e) => e.oid === '2.5.29.19');
    expect(bc?.critical).toBe(true);
  });

  it('parses subject and authority key identifiers', () => {
    expect(root.fields.ski).toBe('25D55E5F530A79188BF799CADA02630217B893F1');
    expect(root.fields.aki).toBe('25D55E5F530A79188BF799CADA02630217B893F1');
  });
});

describe('X.509 leaf certificate', () => {
  const leaf = parseFixture('leaf-cert.pem');

  it('reports version 3', () => {
    expect(leaf.fields.version).toBe(3);
  });

  it('parses the subject CN', () => {
    expect(leaf.fields.subject['2.5.4.3']).toEqual(['test.example.com']);
    expect(leaf.fields.subject['2.5.4.10']).toEqual(['TestOrg']);
  });

  it('parses the issuer as the intermediate CA', () => {
    expect(leaf.fields.issuer['2.5.4.3']).toEqual(['Test Intermediate CA']);
    expect(leaf.fields.issuer['2.5.4.10']).toEqual(['TestOrg']);
    expect(leaf.fields.issuer).not.toEqual(leaf.fields.subject);
  });

  it('parses validity window against fixed timestamps', () => {
    expect(leaf.fields.validity.notBefore).toEqual(new Date(Date.UTC(2026, 5, 12, 8, 25, 26)));
    expect(leaf.fields.validity.notAfter).toEqual(new Date(Date.UTC(2027, 5, 12, 8, 25, 26)));
  });

  it('parses subject alternative names in DER order', () => {
    const san = leaf.fields.san!;
    expect(san).toBeDefined();
    expect(san).toEqual([
      { type: 'DNS', value: 'test.example.com' },
      { type: 'DNS', value: 'www.test.example.com' },
      { type: 'IP', value: '192.168.1.1' },
      { type: 'email', value: 'test@example.com' },
      { type: 'URI', value: 'https://test.example.com' },
    ]);
  });

  it('parses critical key usage', () => {
    expect(leaf.fields.keyUsage).toEqual(['Digital Signature', 'Key Encipherment']);
    const ku = leaf.fields.extensions.find((e) => e.oid === '2.5.29.15');
    expect(ku?.critical).toBe(true);
  });

  it('parses extended key usage for TLS server and client auth', () => {
    expect(leaf.fields.extKeyUsage).toContain('serverAuth (1.3.6.1.5.5.7.3.1)');
    expect(leaf.fields.extKeyUsage).toContain('clientAuth (1.3.6.1.5.5.7.3.2)');
  });

  it('parses basic constraints CA:FALSE', () => {
    expect(leaf.fields.basicConstraints).toEqual({ ca: false });
  });

  it('produces a non-empty signature value', () => {
    expect(leaf.signatureRaw.length).toBeGreaterThan(0);
    expect(leaf.signatureAlgorithm).toBe('1.2.840.113549.1.1.11');
  });
});

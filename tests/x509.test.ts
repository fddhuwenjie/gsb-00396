import { describe, expect, it } from 'vitest';
import { isWithinValidity, parseX509 } from '../src/utils/x509';
import { loadFixtureDer } from './helpers';

const CN = '2.5.4.3';
const O = '2.5.4.10';
const OU = '2.5.4.11';
const C = '2.5.4.6';

function utc(y: number, m: number, d: number, hh = 0, mm = 0, ss = 0): Date {
  return new Date(Date.UTC(y, m - 1, d, hh, mm, ss));
}

describe('root certificate fixture', () => {
  const { fields } = parseX509(loadFixtureDer('root-cert.pem'));

  it('parses subject', () => {
    expect(fields.subject[CN]).toEqual(['Test Root CA']);
    expect(fields.subject[O]).toEqual(['TestOrg']);
    expect(fields.subject[OU]).toEqual(['TestUnit']);
    expect(fields.subject[C]).toEqual(['CN']);
  });

  it('parses issuer (self-signed: identical to subject)', () => {
    expect(fields.issuer).toEqual(fields.subject);
    expect(fields.issuer[CN]).toEqual(['Test Root CA']);
  });

  it('parses validity period', () => {
    expect(fields.validity.notBefore).toEqual(utc(2026, 6, 12, 8, 24, 17));
    expect(fields.validity.notAfter).toEqual(utc(2036, 6, 9, 8, 24, 17));
  });

  it('parses CA basic constraints', () => {
    expect(fields.basicConstraints).toEqual({ ca: true, pathLen: undefined });
  });

  it('evaluates validity at an explicit point in time', () => {
    expect(isWithinValidity(fields.validity, utc(2030, 1, 1))).toBe(true);
    expect(isWithinValidity(fields.validity, utc(2020, 1, 1))).toBe(false);
    expect(isWithinValidity(fields.validity, utc(2040, 1, 1))).toBe(false);
  });
});

describe('leaf certificate fixture', () => {
  const { fields } = parseX509(loadFixtureDer('leaf-cert.pem'));

  it('parses subject', () => {
    expect(fields.subject[CN]).toEqual(['test.example.com']);
    expect(fields.subject[O]).toEqual(['TestOrg']);
    expect(fields.subject[OU]).toEqual(['TestUnit']);
    expect(fields.subject[C]).toEqual(['CN']);
  });

  it('parses issuer (the intermediate CA)', () => {
    expect(fields.issuer[CN]).toEqual(['Test Intermediate CA']);
    expect(fields.issuer[O]).toEqual(['TestOrg']);
  });

  it('parses validity period', () => {
    expect(fields.validity.notBefore).toEqual(utc(2026, 6, 12, 8, 25, 26));
    expect(fields.validity.notAfter).toEqual(utc(2027, 6, 12, 8, 25, 26));
  });

  it('evaluates validity at an explicit point in time', () => {
    expect(isWithinValidity(fields.validity, utc(2027, 1, 1))).toBe(true);
    expect(isWithinValidity(fields.validity, utc(2028, 1, 1))).toBe(false);
    expect(isWithinValidity(fields.validity, utc(2026, 1, 1))).toBe(false);
  });

  it('parses signature algorithm and RSA key size', () => {
    expect(fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(fields.subjectPublicKeyInfo.keySize).toBe(2048);
  });

  it('parses non-CA basic constraints and key usage', () => {
    expect(fields.basicConstraints?.ca).toBe(false);
    expect(fields.keyUsage).toContain('Digital Signature');
    expect(fields.keyUsage).toContain('Key Encipherment');
  });

  it('parses subject alternative names', () => {
    expect(fields.san).toEqual([
      { type: 'DNS', value: 'test.example.com' },
      { type: 'DNS', value: 'www.test.example.com' },
      { type: 'IP', value: '192.168.1.1' },
      { type: 'email', value: 'test@example.com' },
      { type: 'URI', value: 'https://test.example.com' },
    ]);
  });
});

import { describe, it, expect } from 'vitest';
import { tryParseCertificate, getValidityState, evaluateValidity } from './cert-detail';
import { loadFixture } from '../test/fixtures';

type ParseOk = Extract<Awaited<ReturnType<typeof tryParseCertificate>>, { ok: true }>;
type Fields = ParseOk['fields'];

describe('certificate detail — normal certificate (leaf-cert.pem)', () => {
  const pem = loadFixture('leaf-cert.pem');
  const result = tryParseCertificate(pem);

  it('parses successfully', () => {
    expect(result.ok).toBe(true);
  });

  const fields = (result as { ok: true; fields: Fields }).fields;

  it('reports version 3', () => {
    expect(fields.version).toBe(3);
  });

  it('has serial number 2001 (confirmed by `openssl x509 -serial`: 8193 = 0x2001)', () => {
    expect(fields.serialNumber).toContain('0x2001');
    expect(fields.serialNumber).toContain('8193');
  });

  it('uses sha256WithRSAEncryption signature algorithm (confirmed by openssl)', () => {
    expect(fields.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(fields.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
  });

  it('parses the issuer matching the root CA (openssl issuer)', () => {
    expect(fields.issuer['2.5.4.6']).toEqual(['CN']);
    expect(fields.issuer['2.5.4.10']).toEqual(['CertScope Test']);
    expect(fields.issuer['2.5.4.11']).toEqual(['Testing']);
    expect(fields.issuer['2.5.4.3']).toEqual(['CertScope Test Root CA']);
  });

  it('parses the subject (openssl subject)', () => {
    expect(fields.subject['2.5.4.3']).toEqual(['leaf.example.com']);
    expect(fields.subject['2.5.4.11']).toEqual(['Web']);
    expect(fields.subject['2.5.4.10']).toEqual(['CertScope Test']);
  });

  it('parses validity exactly as openssl startdate/enddate', () => {
    expect(fields.validity.notBefore.toISOString()).toBe('2026-08-03T05:57:23.000Z');
    expect(fields.validity.notAfter.toISOString()).toBe('2027-08-03T05:57:23.000Z');
  });

  it('parses an RSA 2048-bit public key (openssl: Public-Key: (2048 bit))', () => {
    expect(fields.subjectPublicKeyInfo.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(fields.subjectPublicKeyInfo.keySize).toBe(2048);
  });

  it('parses SAN entries as shown by openssl (DNS + IP)', () => {
    const dns = fields.san!.filter((e) => e.type === 'DNS').map((e) => e.value);
    const ips = fields.san!.filter((e) => e.type === 'IP').map((e) => e.value);
    expect(dns).toEqual(['leaf.example.com', 'www.leaf.example.com']);
    expect(ips).toEqual(['192.0.2.10']);
  });

  it('marks basic constraints CA:FALSE (openssl)', () => {
    expect(fields.basicConstraints!.ca).toBe(false);
  });
});

describe('certificate detail — expired certificate (expired-cert.pem)', () => {
  const pem = loadFixture('expired-cert.pem');
  const result = tryParseCertificate(pem);

  it('still parses successfully (expired data is structurally valid)', () => {
    expect(result.ok).toBe(true);
  });

  const fields = (result as { ok: true; fields: Fields }).fields;

  it('has serial number 3001 (openssl serial=3001, 12289 = 0x3001)', () => {
    expect(fields.serialNumber).toContain('0x3001');
    expect(fields.serialNumber).toContain('12289');
  });

  it('is self-signed and has the expected subject (openssl)', () => {
    expect(fields.subject).toEqual(fields.issuer);
    expect(fields.subject['2.5.4.3']).toEqual(['expired.example.com']);
    expect(fields.subject['2.5.4.8']).toEqual(['Shanghai']);
    expect(fields.subject['2.5.4.11']).toEqual(['Legacy']);
  });

  it('has the expired window exactly as openssl (2020-01-01 to 2021-01-01)', () => {
    expect(fields.validity.notBefore.toISOString()).toBe('2020-01-01T00:00:00.000Z');
    expect(fields.validity.notAfter.toISOString()).toBe('2021-01-01T00:00:00.000Z');
  });

  it('reports "expired" for a reference time after notAfter', () => {
    const now = new Date(Date.UTC(2026, 7, 3));
    expect(getValidityState(fields, now)).toBe('expired');
  });

  it('reports "valid" for a reference time inside its (past) window', () => {
    const now = new Date(Date.UTC(2020, 5, 1));
    expect(getValidityState(fields, now)).toBe('valid');
  });

  it('reports "not-yet-valid" for a reference time before notBefore', () => {
    const now = new Date(Date.UTC(2019, 0, 1));
    expect(getValidityState(fields, now)).toBe('not-yet-valid');
  });

  it('parses the SAN from the expired cert (openssl DNS:expired.example.com)', () => {
    const dns = fields.san!.filter((e) => e.type === 'DNS').map((e) => e.value);
    expect(dns).toEqual(['expired.example.com']);
  });
});

describe('certificate detail — corrupted / invalid input does not crash', () => {
  function expectError(input: string): string {
    const r = tryParseCertificate(input);
    expect(r.ok).toBe(false);
    if (r.ok) throw new Error('expected parse failure');
    return (r as { ok: false; error: string }).error;
  }

  it('returns a clear error for empty input', () => {
    expect(expectError('')).toMatch(/为空/);
  });

  it('returns a clear error for plain text that is not a certificate', () => {
    expect(expectError('this is absolutely not a certificate').length).toBeGreaterThan(0);
  });

  it('returns a clear error for a PEM block with the wrong label', () => {
    const wrong = [
      '-----BEGIN PRIVATE KEY-----',
      'MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEA',
      '-----END PRIVATE KEY-----',
    ].join('\n');
    expect(expectError(wrong)).toMatch(/PRIVATE KEY|CERTIFICATE/);
  });

  it('returns a clear error for a PEM certificate whose body has been corrupted', () => {
    const good = loadFixture('leaf-cert.pem');
    const lines = good.split('\n');
    const corrupted = lines
      .map((line) => (line.startsWith('MII') ? 'AAAA' + line.slice(4) : line))
      .join('\n');
    expect(expectError(corrupted)).toMatch(/解析失败|损坏|SEQUENCE|Unexpected/i);
  });

  it('returns a clear error for valid base64 that decodes to non-DER garbage', () => {
    const garbage = btoa('\x00\x01\x02\x03not a der sequence at all');
    expect(expectError(garbage).length).toBeGreaterThan(0);
  });
});

describe('evaluateValidity — three states', () => {
  const notBefore = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  const notAfter = new Date(Date.UTC(2027, 0, 1, 0, 0, 0));

  it('returns "not-yet-valid" before notBefore with positive days remaining', () => {
    const now = new Date(Date.UTC(2025, 11, 25, 12, 0, 0));
    const r = evaluateValidity(notBefore, notAfter, now);
    expect(r.state).toBe('not-yet-valid');
    expect(r.label).toBe('尚未生效');
    expect(r.days).toBe(7);
    expect(r.description).toContain('7 天');
  });

  it('returns "valid" inside the window with days until expiry', () => {
    const now = new Date(Date.UTC(2026, 11, 25, 12, 0, 0));
    const r = evaluateValidity(notBefore, notAfter, now);
    expect(r.state).toBe('valid');
    expect(r.label).toBe('当前有效');
    expect(r.days).toBe(7);
    expect(r.description).toContain('7 天');
  });

  it('returns "expired" after notAfter with days since expiry', () => {
    const now = new Date(Date.UTC(2027, 0, 10, 12, 0, 0));
    const r = evaluateValidity(notBefore, notAfter, now);
    expect(r.state).toBe('expired');
    expect(r.label).toBe('已过期');
    expect(r.days).toBe(9);
    expect(r.description).toContain('9 天');
  });
});

describe('evaluateValidity — exact boundary timestamps', () => {
  const notBefore = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  const notAfter = new Date(Date.UTC(2027, 0, 1, 0, 0, 0));

  it('is valid at exactly notBefore (inclusive)', () => {
    const r = evaluateValidity(notBefore, notAfter, new Date(notBefore.getTime()));
    expect(r.state).toBe('valid');
    expect(r.days).toBe(365);
  });

  it('is valid at exactly notAfter (inclusive)', () => {
    const r = evaluateValidity(notBefore, notAfter, new Date(notAfter.getTime()));
    expect(r.state).toBe('valid');
    expect(r.days).toBe(0);
  });

  it('is not-yet-valid one millisecond before notBefore', () => {
    const r = evaluateValidity(notBefore, notAfter, new Date(notBefore.getTime() - 1));
    expect(r.state).toBe('not-yet-valid');
    expect(r.days).toBe(1);
  });

  it('is expired one millisecond after notAfter (same UTC calendar day)', () => {
    const r = evaluateValidity(notBefore, notAfter, new Date(notAfter.getTime() + 1));
    expect(r.state).toBe('expired');
    expect(r.days).toBe(0);
  });
});

describe('evaluateValidity — timezone independence', () => {
  const notBefore = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  const notAfter = new Date(Date.UTC(2027, 0, 1, 0, 0, 0));

  it('uses UTC calendar days, so local offset does not change the result', () => {
    const getTimezoneOffset = Date.prototype.getTimezoneOffset;
    Date.prototype.getTimezoneOffset = () => -480;
    try {
      const r1 = evaluateValidity(notBefore, notAfter, new Date(Date.UTC(2026, 11, 25, 23, 0, 0)));
      Date.prototype.getTimezoneOffset = () => 300;
      const r2 = evaluateValidity(notBefore, notAfter, new Date(Date.UTC(2026, 11, 25, 23, 0, 0)));
      expect(r1).toEqual(r2);
      expect(r1.days).toBe(7);
      expect(r1.state).toBe('valid');
    } finally {
      Date.prototype.getTimezoneOffset = getTimezoneOffset;
    }
  });

  it('counts days across the UTC day boundary, not a 24h rolling window', () => {
    const now = new Date(Date.UTC(2026, 0, 1, 23, 59, 59));
    const r = evaluateValidity(notBefore, notAfter, now);
    expect(r.state).toBe('valid');
    expect(r.days).toBe(365);
  });

  it('rolls over to one fewer day just after midnight UTC on the next calendar day', () => {
    const justAfterMidnight = new Date(Date.UTC(2026, 0, 2, 0, 0, 1));
    const r = evaluateValidity(notBefore, notAfter, justAfterMidnight);
    expect(r.state).toBe('valid');
    expect(r.days).toBe(364);
  });

  it('treats the same instant created from different local constructions identically', () => {
    const fromUTC = new Date(Date.UTC(2026, 5, 15, 12, 0, 0));
    const fromISO = new Date('2026-06-15T12:00:00.000Z');
    expect(evaluateValidity(notBefore, notAfter, fromUTC)).toEqual(
      evaluateValidity(notBefore, notAfter, fromISO),
    );
  });
});

describe('evaluateValidity — determinism', () => {
  const notBefore = new Date(Date.UTC(2026, 0, 1, 0, 0, 0));
  const notAfter = new Date(Date.UTC(2027, 0, 1, 0, 0, 0));
  const now = new Date(Date.UTC(2026, 5, 1, 0, 0, 0));

  it('returns the identical result for the same inputs on repeated calls', () => {
    const a = evaluateValidity(notBefore, notAfter, now);
    const b = evaluateValidity(notBefore, notAfter, now);
    expect(a).toEqual(b);
  });
});

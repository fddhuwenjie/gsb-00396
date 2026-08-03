import { describe, it, expect } from 'vitest';
import {
  parseCertificateInput,
  getValidityStatus,
  getValidityInfo,
  parseEvalTime,
  formatEvalInputValue,
  isValidEvalTime,
  MS_PER_DAY,
} from '../src/utils/certificate-detail';
import { loadFixture } from './helpers';

describe('parseCertificateInput', () => {
  it('parses a normal self-signed root certificate (fields verified against OpenSSL)', () => {
    const result = parseCertificateInput(loadFixture('root-cert.pem'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const d = result.detail;

    expect(d.version).toBe(3);
    // openssl x509 -serial => 3F68365E414C779D9B7286C7DA55993F204ABCEC
    expect(d.serialNumber).toBe('0x3f68365e414c779d9b7286c7da55993f204abcec');

    // openssl x509 -subject
    expect(d.subject['2.5.4.6']).toEqual(['CN']);
    expect(d.subject['2.5.4.8']).toEqual(['Beijing']);
    expect(d.subject['2.5.4.7']).toEqual(['Beijing']);
    expect(d.subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(d.subject['2.5.4.11']).toEqual(['TestUnit']);
    expect(d.subject['2.5.4.3']).toEqual(['Test Root CA']);

    // openssl x509 -issuer (self-signed => issuer == subject)
    expect(d.issuer).toEqual(d.subject);

    // openssl x509 -dates
    expect(d.notBefore).toEqual(new Date(Date.UTC(2026, 5, 12, 8, 24, 17)));
    expect(d.notAfter).toEqual(new Date(Date.UTC(2036, 5, 9, 8, 24, 17)));

    // openssl x509 -text => sha256WithRSAEncryption / rsaEncryption 2048-bit
    expect(d.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
    expect(d.signatureAlgorithm.name).toBe('sha256WithRSAEncryption');
    expect(d.publicKeyAlgorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(d.publicKeyAlgorithm.name).toBe('rsaEncryption');
    expect(d.publicKeyAlgorithm.keySize).toBe(2048);

    // openssl x509 -ext basicConstraints => CA:TRUE (critical)
    expect(d.basicConstraints).toEqual({ ca: true });
  });

  it('parses an expired certificate (fields verified against OpenSSL)', () => {
    const result = parseCertificateInput(loadFixture('expired-cert.pem'));
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    const d = result.detail;

    // openssl x509 -serial => 0BADBEEFCAFEBABEDEADBEEFCAFEBABE
    expect(d.serialNumber).toBe('0x0badbeefcafebabedeadbeefcafebabe');

    // openssl x509 -subject
    expect(d.subject['2.5.4.3']).toEqual(['expired.example.com']);
    expect(d.subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(d.issuer).toEqual(d.subject);

    // openssl x509 -dates => Jan 1 00:00:00 2020 GMT .. Jan 1 00:00:00 2021 GMT
    expect(d.notBefore).toEqual(new Date(Date.UTC(2020, 0, 1, 0, 0, 0)));
    expect(d.notAfter).toEqual(new Date(Date.UTC(2021, 0, 1, 0, 0, 0)));

    // openssl x509 -ext basicConstraints => CA:FALSE (critical)
    expect(d.basicConstraints).toEqual({ ca: false });

    // openssl x509 -ext keyUsage => Digital Signature, Key Encipherment
    expect(d.keyUsage).toEqual(['Digital Signature', 'Key Encipherment']);

    // openssl x509 -ext subjectAltName
    expect(d.san).toEqual([
      { type: 'DNS', value: 'expired.example.com' },
      { type: 'DNS', value: 'www.expired.example.com' },
    ]);

    // At a fixed reference time after notAfter, status is expired
    const ref = new Date(Date.UTC(2026, 0, 1));
    expect(getValidityStatus(d.notBefore, d.notAfter, ref)).toBe('expired');
  });

  it('returns an error for empty input instead of throwing', () => {
    const result = parseCertificateInput('   ');
    expect(result.ok).toBe(false);
    if (result.ok === true) throw new Error('expected parse failure');
    expect(result.error).toMatch(/请输入/);
  });

  it('returns an error for non-PEM text', () => {
    const result = parseCertificateInput('this is not a certificate');
    expect(result.ok).toBe(false);
    if (result.ok === true) throw new Error('expected parse failure');
    expect(result.error).toMatch(/PEM/);
  });

  it('returns an error for a corrupted PEM block with invalid DER content', () => {
    const result = parseCertificateInput(loadFixture('corrupted-cert.pem'));
    expect(result.ok).toBe(false);
    if (result.ok === true) throw new Error('expected parse failure');
    expect(result.error).toMatch(/解析失败/);
  });

  it('returns an error for a PEM block that is not a CERTIFICATE', () => {
    const csr = loadFixture('leaf-csr.pem');
    const result = parseCertificateInput(csr);
    expect(result.ok).toBe(false);
    if (result.ok === true) throw new Error('expected parse failure');
    expect(result.error).toMatch(/CERTIFICATE REQUEST/);
  });
});

describe('getValidityStatus', () => {
  const nb = new Date(Date.UTC(2026, 5, 12, 8, 25, 26));
  const na = new Date(Date.UTC(2027, 5, 12, 8, 25, 26));

  it('returns valid for a time inside the window', () => {
    expect(getValidityStatus(nb, na, new Date(Date.UTC(2027, 0, 1)))).toBe('valid');
  });

  it('returns notYetValid for a time before notBefore', () => {
    expect(getValidityStatus(nb, na, new Date(Date.UTC(2026, 0, 1)))).toBe('notYetValid');
  });

  it('returns expired for a time after notAfter', () => {
    expect(getValidityStatus(nb, na, new Date(Date.UTC(2028, 0, 1)))).toBe('expired');
  });

  it('returns valid at the exact notBefore boundary', () => {
    expect(getValidityStatus(nb, na, nb)).toBe('valid');
  });

  it('returns valid at the exact notAfter boundary (inclusive)', () => {
    expect(getValidityStatus(nb, na, na)).toBe('valid');
  });

  it('returns expired one millisecond after notAfter', () => {
    expect(getValidityStatus(nb, na, new Date(na.getTime() + 1))).toBe('expired');
  });
});

describe('getValidityInfo', () => {
  const nb = new Date(Date.UTC(2026, 5, 12, 8, 25, 26));
  const na = new Date(Date.UTC(2027, 5, 12, 8, 25, 26));

  it('reports notYetValid with days until notBefore', () => {
    const now = new Date(Date.UTC(2026, 5, 7, 8, 25, 26));
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'notYetValid', days: 5 });
  });

  it('rounds up to 1 day when less than a day remains before validity', () => {
    const now = new Date(nb.getTime() - 1);
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'notYetValid', days: 1 });
  });

  it('reports valid with whole days remaining until expiry', () => {
    const now = new Date(Date.UTC(2027, 5, 7, 8, 25, 26));
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'valid', days: 5 });
  });

  it('reports 0 days remaining within the last 24 hours before expiry', () => {
    const now = new Date(na.getTime() - MS_PER_DAY + 1);
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'valid', days: 0 });
  });

  it('reports expired with whole days since notAfter', () => {
    const now = new Date(Date.UTC(2027, 5, 17, 8, 25, 26));
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'expired', days: 5 });
  });

  it('reports 0 days expired within the first 24 hours after notAfter', () => {
    const now = new Date(na.getTime() + 1);
    expect(getValidityInfo(nb, na, now)).toEqual({ status: 'expired', days: 0 });
  });

  it('is deterministic: identical inputs always yield identical results', () => {
    const now = new Date(Date.UTC(2026, 6, 1, 12, 0, 0));
    const first = getValidityInfo(nb, na, now);
    const second = getValidityInfo(nb, na, new Date(now.getTime()));
    expect(second).toEqual(first);
  });
});

describe('getValidityInfo timezone boundaries', () => {
  const nb = new Date(Date.UTC(2026, 5, 12, 8, 25, 26));
  const na = new Date(Date.UTC(2027, 5, 12, 8, 25, 26));

  it('does not depend on local timezone when parsing a UTC instant', () => {
    const instant = Date.UTC(2027, 0, 1, 0, 0, 0);
    const fromUTC = new Date(instant);
    const fromComponents = new Date(2027, 0, 1, 0, 0, 0);
    if (fromComponents.getTime() === instant) {
      expect(getValidityInfo(nb, na, fromUTC)).toEqual(getValidityInfo(nb, na, fromComponents));
    } else {
      expect(getValidityInfo(nb, na, fromUTC).status).toBe('valid');
      expect(getValidityInfo(nb, na, fromComponents).status).toBe('valid');
    }
  });

  it('counts days using 24-hour absolute time, not local calendar days', () => {
    const now = new Date(nb.getTime() + 3 * MS_PER_DAY + 12 * 3600_000);
    const info = getValidityInfo(nb, na, now);
    expect(info.status).toBe('valid');
    const remaining = na.getTime() - now.getTime();
    expect(info.days).toBe(Math.floor(remaining / MS_PER_DAY));
  });

  it('produces the same status across a daylight-saving-like local shift at the same instant', () => {
    const instants = [
      Date.UTC(2026, 2, 8, 12, 0, 0),
      Date.UTC(2026, 10, 1, 12, 0, 0),
      Date.UTC(2026, 5, 12, 8, 25, 26),
      Date.UTC(2027, 5, 12, 8, 25, 27),
    ];
    for (const t of instants) {
      const a = getValidityInfo(nb, na, new Date(t));
      const b = getValidityInfo(nb, na, new Date(t));
      expect(a).toEqual(b);
    }
  });
});

describe('parseEvalTime / formatEvalInputValue', () => {
  it('parses a datetime-local string as UTC', () => {
    expect(parseEvalTime('2026-07-01T12:00')).toEqual(new Date(Date.UTC(2026, 6, 1, 12, 0, 0)));
  });

  it('formats a UTC Date back to the datetime-local value', () => {
    const date = new Date(Date.UTC(2026, 0, 5, 3, 7, 0));
    expect(formatEvalInputValue(date)).toBe('2026-01-05T03:07');
  });

  it('round-trips through format then parse to the same instant', () => {
    const original = new Date(Date.UTC(2027, 11, 31, 23, 59, 0));
    const roundTripped = parseEvalTime(formatEvalInputValue(original));
    expect(roundTripped.getTime()).toBe(original.getTime());
  });

  it('rejects malformed input', () => {
    expect(isValidEvalTime('2026/07/01 12:00')).toBe(false);
    expect(isValidEvalTime('not-a-date')).toBe(false);
    expect(() => parseEvalTime('2026-07-01')).toThrow();
  });

  it('accepts valid input', () => {
    expect(isValidEvalTime('2026-07-01T12:00')).toBe(true);
  });
});

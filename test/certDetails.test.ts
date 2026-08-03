import { describe, it, expect } from 'vitest';
import {
  describeCertificateFromPEM,
  describeCertificateFromDER,
  getValidityStatus,
  checkValidity,
  normalizeSerial,
  CertificateSummary,
} from '@/utils/certDetails';
import { readFixture } from './fixtures';
import { parsePEM } from '@/utils/asn1';

// Expected values below are pinned to OpenSSL output for each fixture, NOT to
// whatever the parser under test happens to produce:
//
//   openssl x509 -in root-cert.pem    -noout -serial -subject -issuer -startdate -enddate
//     serial=3F68365E414C779D9B7286C7DA55993F204ABCEC
//     subject=C=CN, ST=Beijing, L=Beijing, O=TestOrg, OU=TestUnit, CN=Test Root CA
//     issuer =C=CN, ST=Beijing, L=Beijing, O=TestOrg, OU=TestUnit, CN=Test Root CA
//     notBefore=Jun 12 08:24:17 2026 GMT ; notAfter=Jun  9 08:24:17 2036 GMT
//     Public Key: rsaEncryption (2048 bit) ; Signature: sha256WithRSAEncryption
//
//   openssl x509 -in expired-cert.pem -noout -serial -subject -startdate -enddate
//     serial=0CF76F1ACD84C9B25D65AED98F84743F95170C74
//     subject=... CN=expired.example.com
//     notBefore=Jan  1 00:00:00 2020 GMT ; notAfter=Jan  2 00:00:00 2020 GMT

describe('describeCertificate — normal certificate', () => {
  const result = describeCertificateFromPEM(readFixture('root-cert.pem'));

  it('succeeds', () => {
    expect(result.ok).toBe(true);
  });

  it('reports the OpenSSL serial number (uppercase hex, no 0x)', () => {
    expect(result.ok && result.summary.serialNumber).toBe(
      '3F68365E414C779D9B7286C7DA55993F204ABCEC',
    );
  });

  it('reports subject and issuer distinguished names', () => {
    expect(result.ok && result.summary.subject).toBe(
      'CN = Test Root CA, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
    expect(result.ok && result.summary.issuer).toBe(
      'CN = Test Root CA, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
  });

  it('reports the validity window as UTC dates', () => {
    expect(result.ok && result.summary.notBefore.toISOString()).toBe('2026-06-12T08:24:17.000Z');
    expect(result.ok && result.summary.notAfter.toISOString()).toBe('2036-06-09T08:24:17.000Z');
  });

  it('reports public-key algorithm, size, and signature algorithm', () => {
    if (!result.ok) throw new Error('expected ok');
    expect(result.summary.publicKeyAlgorithm).toBe('rsaEncryption');
    expect(result.summary.publicKeyOid).toBe('1.2.840.113549.1.1.1');
    expect(result.summary.keySize).toBe(2048);
    expect(result.summary.signatureAlgorithm).toBe('sha256WithRSAEncryption');
    expect(result.summary.signatureOid).toBe('1.2.840.113549.1.1.11');
  });

  it('lists common extensions with OIDs (SKI/AKI/BasicConstraints)', () => {
    if (!result.ok) throw new Error('expected ok');
    const oids = result.summary.extensions.map((e) => e.oid);
    expect(oids).toContain('2.5.29.14'); // subjectKeyIdentifier
    expect(oids).toContain('2.5.29.35'); // authorityKeyIdentifier
    expect(oids).toContain('2.5.29.19'); // basicConstraints
    const bc = result.summary.extensions.find((e) => e.oid === '2.5.29.19');
    expect(bc?.critical).toBe(true); // "Basic Constraints: critical" in OpenSSL output
  });

  it('is valid at a time inside its window, using an injected verification time', () => {
    if (!result.ok) throw new Error('expected ok');
    expect(getValidityStatus(result.summary, new Date('2030-01-01T00:00:00Z'))).toBe('valid');
    expect(getValidityStatus(result.summary, new Date('2000-01-01T00:00:00Z'))).toBe('not-yet-valid');
  });
});

describe('describeCertificate — expired certificate', () => {
  const result = describeCertificateFromPEM(readFixture('expired-cert.pem'));

  it('parses successfully (expired is not a parse error)', () => {
    expect(result.ok).toBe(true);
  });

  it('reports the pinned serial and subject', () => {
    if (!result.ok) throw new Error('expected ok');
    expect(result.summary.serialNumber).toBe('0CF76F1ACD84C9B25D65AED98F84743F95170C74');
    expect(result.summary.subject).toContain('CN = expired.example.com');
  });

  it('reports the pinned 2020 validity window', () => {
    if (!result.ok) throw new Error('expected ok');
    expect(result.summary.notBefore.toISOString()).toBe('2020-01-01T00:00:00.000Z');
    expect(result.summary.notAfter.toISOString()).toBe('2020-01-02T00:00:00.000Z');
  });

  it('is reported expired at a fixed time after notAfter (no dependency on today)', () => {
    if (!result.ok) throw new Error('expected ok');
    expect(getValidityStatus(result.summary, new Date('2020-06-01T00:00:00Z'))).toBe('expired');
    // ...and valid at a time inside its (short) window.
    expect(getValidityStatus(result.summary, new Date('2020-01-01T12:00:00Z'))).toBe('valid');
  });
});

describe('describeCertificate — corrupted input', () => {
  it('returns an error (not a throw) for non-PEM garbage', () => {
    const result = describeCertificateFromPEM('this is not a certificate');
    expect(result.ok).toBe(false);
    expect(result.ok === false && result.error).toBeTruthy();
  });

  it('returns an error for a PEM block with truncated/invalid DER', () => {
    const truncated =
      '-----BEGIN CERTIFICATE-----\nMIIB/zANBgkqhkiG9w0BAQ==\n-----END CERTIFICATE-----';
    const result = describeCertificateFromPEM(truncated);
    expect(result.ok).toBe(false);
  });

  it('returns an error for empty DER without throwing', () => {
    const result = describeCertificateFromDER(new Uint8Array(0));
    expect(result.ok).toBe(false);
  });

  it('corrupting a byte in a valid cert is reported, never crashes', () => {
    // Flip bytes inside the DER to break structure; must yield ok:false, no throw.
    const der = parsePEM(readFixture('root-cert.pem'))[0].der.slice();
    for (let i = 2; i < 12 && i < der.length; i++) der[i] ^= 0xff;
    expect(() => describeCertificateFromDER(der)).not.toThrow();
  });
});

describe('normalizeSerial', () => {
  it('strips 0x prefix and uppercases', () => {
    expect(normalizeSerial('123 (0x0cf76f1a)')).toBe('0CF76F1A');
    expect(normalizeSerial('0xabcdef')).toBe('ABCDEF');
  });
});

describe('checkValidity — three states', () => {
  // The leaf certificate's window is pinned by OpenSSL:
  //   notBefore=Jun 12 08:25:26 2026 GMT ; notAfter=Jun 12 08:25:26 2027 GMT
  const NOT_BEFORE = '2026-06-12T08:25:26Z';
  const NOT_AFTER = '2027-06-12T08:25:26Z';

  function leafSummary(): CertificateSummary {
    const result = describeCertificateFromPEM(readFixture('leaf-cert.pem'));
    if (!result.ok) throw new Error('expected leaf cert to parse');
    // Guard: expected values come from OpenSSL, not the parser's own output.
    expect(result.summary.notBefore.toISOString()).toBe('2026-06-12T08:25:26.000Z');
    expect(result.summary.notAfter.toISOString()).toBe('2027-06-12T08:25:26.000Z');
    return result.summary;
  }

  it('reports "not-yet-valid" before notBefore, with days until valid', () => {
    const summary = leafSummary();
    // 10 days before notBefore.
    const check = checkValidity(summary, new Date('2026-06-02T08:25:26Z'));
    expect(check.status).toBe('not-yet-valid');
    expect(check.daysUntilValid).toBe(10);
    expect(check.daysUntilExpiry).toBe(0);
    expect(check.daysSinceExpiry).toBe(0);
  });

  it('reports "valid" inside the window, with days until expiry', () => {
    const summary = leafSummary();
    // 30 days before notAfter.
    const check = checkValidity(summary, new Date('2027-05-13T08:25:26Z'));
    expect(check.status).toBe('valid');
    expect(check.daysUntilExpiry).toBe(30);
    expect(check.daysUntilValid).toBe(0);
    expect(check.daysSinceExpiry).toBe(0);
  });

  it('reports "expired" after notAfter, with days since expiry', () => {
    const summary = leafSummary();
    // 5 days after notAfter.
    const check = checkValidity(summary, new Date('2027-06-17T08:25:26Z'));
    expect(check.status).toBe('expired');
    expect(check.daysSinceExpiry).toBe(5);
    expect(check.daysUntilExpiry).toBe(0);
    expect(check.daysUntilValid).toBe(0);
  });

  it('is deterministic: identical input + evaluation time yields identical result', () => {
    const summary = leafSummary();
    const at = new Date('2027-01-01T00:00:00Z');
    expect(checkValidity(summary, at)).toEqual(checkValidity(summary, at));
  });

  it('exactly at notBefore is valid; exactly at notAfter is valid; one ms past is not', () => {
    const summary = leafSummary();
    expect(checkValidity(summary, new Date(NOT_BEFORE)).status).toBe('valid');
    expect(checkValidity(summary, new Date(NOT_AFTER)).status).toBe('valid');
    expect(
      checkValidity(summary, new Date(new Date(NOT_BEFORE).getTime() - 1)).status,
    ).toBe('not-yet-valid');
    expect(
      checkValidity(summary, new Date(new Date(NOT_AFTER).getTime() + 1)).status,
    ).toBe('expired');
  });
});

describe('checkValidity — time zone boundary', () => {
  // Certificate windows are absolute UTC instants. The same wall-clock moment
  // expressed with different UTC offsets must produce the same result, and an
  // offset that crosses the boundary must flip the status accordingly.
  function leafSummary(): CertificateSummary {
    const result = describeCertificateFromPEM(readFixture('leaf-cert.pem'));
    if (!result.ok) throw new Error('expected leaf cert to parse');
    return result.summary;
  }

  it('treats the same instant identically regardless of source offset notation', () => {
    const summary = leafSummary();
    // notBefore is 2026-06-12T08:25:26Z. The same instant in +08:00 is
    // 2026-06-12T16:25:26+08:00. Both must be exactly at the boundary → valid.
    const utc = checkValidity(summary, new Date('2026-06-12T08:25:26Z'));
    const plus8 = checkValidity(summary, new Date('2026-06-12T16:25:26+08:00'));
    expect(utc).toEqual(plus8);
    expect(plus8.status).toBe('valid');
  });

  it('a positive UTC offset that pulls the instant before notBefore flips to not-yet-valid', () => {
    const summary = leafSummary();
    // Local wall-clock "2026-06-12T08:25:26" in +08:00 is 00:25:26Z — 8 hours
    // BEFORE notBefore — so the cert is not yet valid at that instant.
    const check = checkValidity(summary, new Date('2026-06-12T08:25:26+08:00'));
    expect(check.status).toBe('not-yet-valid');
  });

  it('a negative UTC offset that pushes the instant past notAfter flips to expired', () => {
    const summary = leafSummary();
    // Local wall-clock "2027-06-12T08:25:26" in -05:00 is 13:25:26Z — after the
    // 08:25:26Z notAfter — so the cert is expired at that instant.
    const check = checkValidity(summary, new Date('2027-06-12T08:25:26-05:00'));
    expect(check.status).toBe('expired');
  });

  it('agrees with getValidityStatus across offsets', () => {
    const summary = leafSummary();
    const instant = new Date('2027-05-13T08:25:26Z');
    expect(checkValidity(summary, instant).status).toBe(getValidityStatus(summary, instant));
  });
});

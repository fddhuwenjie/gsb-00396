import { describe, it, expect } from 'vitest';
import { parsePEM } from '@/utils/asn1';
import { parseX509, formatDN } from '@/utils/x509';
import { parseCertFromDER, validateChain } from '@/utils/chain';
import { readFixture } from './fixtures';

// Fixtures are self-signed/test PKI PEMs with no private keys. See README for
// provenance. Expected values are pinned to `openssl x509` output for each file.

function firstDer(pem: string): Uint8Array {
  const blocks = parsePEM(pem);
  expect(blocks.length).toBeGreaterThan(0);
  return blocks[0].der;
}

describe('X.509 root certificate parsing', () => {
  const { fields } = parseX509(firstDer(readFixture('root-cert.pem')));

  it('parses the subject distinguished name', () => {
    expect(formatDN(fields.subject)).toBe(
      'CN = Test Root CA, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
  });

  it('is self-issued: subject equals issuer', () => {
    expect(formatDN(fields.issuer)).toBe(formatDN(fields.subject));
  });

  it('parses the validity period as UTC dates', () => {
    expect(fields.validity.notBefore.toISOString()).toBe('2026-06-12T08:24:17.000Z');
    expect(fields.validity.notAfter.toISOString()).toBe('2036-06-09T08:24:17.000Z');
  });

  it('exposes the serial number', () => {
    expect(fields.serialNumber.toUpperCase()).toContain(
      '3F68365E414C779D9B7286C7DA55993F204ABCEC',
    );
  });
});

describe('X.509 leaf certificate parsing', () => {
  const { fields } = parseX509(firstDer(readFixture('leaf-cert.pem')));

  it('parses the leaf subject', () => {
    expect(formatDN(fields.subject)).toBe(
      'CN = test.example.com, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
  });

  it('parses the issuer as the intermediate CA', () => {
    expect(formatDN(fields.issuer)).toBe(
      'CN = Test Intermediate CA, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
  });

  it('parses the validity period', () => {
    expect(fields.validity.notBefore.toISOString()).toBe('2026-06-12T08:25:26.000Z');
    expect(fields.validity.notAfter.toISOString()).toBe('2027-06-12T08:25:26.000Z');
  });
});

describe('certificate validity uses the supplied verification time', () => {
  const cert = parseCertFromDER(
    firstDer(readFixture('root-cert.pem')),
    readFixture('root-cert.pem'),
  );

  it('reports the certificate valid at a time inside its window', async () => {
    const insideWindow = new Date('2027-01-01T00:00:00Z');
    const result = await validateChain([cert], [], insideWindow);
    expect(result.results[0].validityOk).toBe(true);
  });

  it('reports "not yet valid" before notBefore', async () => {
    const beforeWindow = new Date('2020-01-01T00:00:00Z');
    const result = await validateChain([cert], [], beforeWindow);
    expect(result.results[0].validityOk).toBe(false);
    expect(result.results[0].validityError).toMatch(/not yet valid/i);
  });

  it('reports "expired" after notAfter', async () => {
    const afterWindow = new Date('2099-01-01T00:00:00Z');
    const result = await validateChain([cert], [], afterWindow);
    expect(result.results[0].validityOk).toBe(false);
    expect(result.results[0].validityError).toMatch(/expired/i);
  });
});

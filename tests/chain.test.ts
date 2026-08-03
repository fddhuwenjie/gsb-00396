import { describe, it, expect } from 'vitest';
import { parsePEM } from '../src/utils/asn1';
import { parseCertFromDER, buildChain, validateChain } from '../src/utils/chain';
import type { ParsedCert } from '../src/utils/chain';
import { loadFixture } from './helpers';

function parseCert(name: string): ParsedCert {
  const pem = loadFixture(name);
  const der = parsePEM(pem)[0].der;
  return parseCertFromDER(der, pem);
}

describe('Certificate chain validation', () => {
  const leaf = parseCert('leaf-cert.pem');
  const intermediate = parseCert('intermediate-cert.pem');
  const root = parseCert('root-cert.pem');

  it('builds an ordered chain leaf -> intermediate -> root by issuer/subject', () => {
    const chain = buildChain(leaf, [intermediate], [root]);
    expect(chain.map((c) => c.fields.subject['2.5.4.3']?.[0])).toEqual([
      'test.example.com',
      'Test Intermediate CA',
      'Test Root CA',
    ]);
  });

  it('validates the full chain at a fixed time inside the validity window', async () => {
    const chain = buildChain(leaf, [intermediate], [root]);
    const verificationTime = new Date(Date.UTC(2026, 6, 1, 12, 0, 0));
    const result = await validateChain(chain, [], verificationTime);

    expect(result.valid).toBe(true);
    expect(result.results).toHaveLength(3);
    for (const step of result.results) {
      expect(step.validityOk).toBe(true);
      expect(step.signatureValid).toBe(true);
      expect(step.signatureError).toBeUndefined();
    }
    expect(result.results[2].selfSigned).toBe(true);
  });

  it('reports expiration when the fixed time is after leaf notAfter', async () => {
    const chain = buildChain(leaf, [intermediate], [root]);
    const afterExpiry = new Date(Date.UTC(2027, 6, 1, 12, 0, 0));
    const result = await validateChain(chain, [], afterExpiry);

    expect(result.valid).toBe(false);
    const leafStep = result.results[0];
    expect(leafStep.validityOk).toBe(false);
    expect(leafStep.validityError).toMatch(/expired/);
    expect(result.results[1].validityOk).toBe(true);
    expect(result.results[2].validityOk).toBe(true);
  });

  it('reports "not yet valid" when the fixed time is before notBefore', async () => {
    const chain = buildChain(leaf, [intermediate], [root]);
    const beforeIssuance = new Date(Date.UTC(2026, 5, 1, 12, 0, 0));
    const result = await validateChain(chain, [], beforeIssuance);

    expect(result.valid).toBe(false);
    for (const step of result.results) {
      expect(step.validityOk).toBe(false);
      expect(step.validityError).toMatch(/not yet valid/);
    }
  });

  it('verifies a self-signed root signature at a fixed time', async () => {
    const chain = buildChain(root, [], [root]);
    const result = await validateChain(chain, [], new Date(Date.UTC(2026, 6, 1)));

    expect(result.valid).toBe(true);
    expect(result.results[0].selfSigned).toBe(true);
    expect(result.results[0].signatureValid).toBe(true);
  });
});

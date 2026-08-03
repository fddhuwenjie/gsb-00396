import { describe, it, expect } from 'vitest';
import { parsePEM } from './asn1';
import { parseCertFromDER, buildChain, validateChain } from './chain';
import { loadFixture } from '../test/fixtures';

function parsePEMCert(name: string) {
  const pem = loadFixture(name);
  const { der } = parsePEM(pem)[0];
  return parseCertFromDER(der, pem);
}

describe('chain validation with an explicit reference time', () => {
  const root = parsePEMCert('root-cert.pem');
  const leaf = parsePEMCert('leaf-cert.pem');

  it('builds a leaf -> root chain by matching issuer/subject DN', () => {
    const chain = buildChain(leaf, [], [root]);
    expect(chain).toHaveLength(2);
    expect(chain[0]).toBe(leaf);
    expect(chain[1]).toBe(root);
  });

  it('validates the signature chain successfully at a fixed time inside the window', async () => {
    const chain = buildChain(leaf, [], [root]);
    const referenceTime = new Date(Date.UTC(2027, 0, 15, 12, 0, 0));
    const result = await validateChain(chain, [], referenceTime);

    expect(result.valid).toBe(true);
    expect(result.results).toHaveLength(2);

    const leafResult = result.results[0];
    expect(leafResult.selfSigned).toBe(false);
    expect(leafResult.validityOk).toBe(true);
    expect(leafResult.signatureValid).toBe(true);
    expect(leafResult.nameChainValid).toBe(true);

    const rootResult = result.results[1];
    expect(rootResult.selfSigned).toBe(true);
    expect(rootResult.signatureValid).toBe(true);
  });

  it('reports a not-yet-valid certificate at a reference time before notBefore', async () => {
    const chain = buildChain(leaf, [], [root]);
    const before = new Date(Date.UTC(2020, 0, 1));
    const result = await validateChain(chain, [], before);

    expect(result.valid).toBe(false);
    const leafResult = result.results[0];
    expect(leafResult.validityOk).toBe(false);
    expect(leafResult.validityError).toMatch(/not yet valid/i);
  });

  it('reports an expired certificate at a reference time after notAfter', async () => {
    const chain = buildChain(leaf, [], [root]);
    const after = new Date(Date.UTC(2030, 0, 1));
    const result = await validateChain(chain, [], after);

    expect(result.valid).toBe(false);
    const leafResult = result.results[0];
    expect(leafResult.validityOk).toBe(false);
    expect(leafResult.validityError).toMatch(/expired/i);
  });

  it('rejects a chain whose leaf has no issuer in the trust store', async () => {
    const result = await validateChain(
      [leaf],
      [],
      new Date(Date.UTC(2027, 0, 15)),
    );
    expect(result.valid).toBe(false);
    expect(result.results[0].signatureError).toMatch(/No parent certificate/i);
  });
});

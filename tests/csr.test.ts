import { describe, expect, it } from 'vitest';
import { parseCSR } from '../src/utils/csr';
import { loadFixtureDer } from './helpers';

describe('CSR fixture', () => {
  const csr = parseCSR(loadFixtureDer('leaf-csr.pem'));

  it('parses CSR version', () => {
    expect(csr.version).toBe(0);
  });

  it('parses subject fields', () => {
    expect(csr.subject['2.5.4.3']).toEqual(['test.example.com']);
    expect(csr.subject['2.5.4.10']).toEqual(['TestOrg']);
    expect(csr.subject['2.5.4.11']).toEqual(['TestUnit']);
    expect(csr.subject['2.5.4.6']).toEqual(['CN']);
  });

  it('parses signature algorithm', () => {
    expect(csr.signatureAlgorithm.oid).toBe('1.2.840.113549.1.1.11');
  });

  it('parses public key algorithm and size', () => {
    expect(csr.publicKey.algorithm.oid).toBe('1.2.840.113549.1.1.1');
    expect(csr.publicKey.keySize).toBe(2048);
  });

  it('has no requested SAN extension', () => {
    expect(csr.san).toBeUndefined();
  });
});

import { describe, it, expect } from 'vitest';
import { parsePEM, parseASN1 } from '@/utils/asn1';
import { parseDN, formatDN } from '@/utils/x509';
import { readFixture } from './fixtures';

// A PKCS#10 CertificationRequest is:
//   SEQUENCE {
//     CertificationRequestInfo SEQUENCE {
//       version           INTEGER,      -- 0 for v1
//       subject           Name,
//       subjectPKInfo     SubjectPublicKeyInfo,
//       attributes        [0] ...
//     },
//     signatureAlgorithm  AlgorithmIdentifier,
//     signature           BIT STRING
//   }
// The app has no dedicated CSR parser, so these tests decode the request with
// the same ASN.1/DN primitives the browser app relies on.

const blocks = parsePEM(readFixture('leaf-csr.pem'));
const csr = parseASN1(blocks[0].der);
const cri = csr.children![0];

describe('CSR basic fields', () => {
  it('is recognized as a CERTIFICATE REQUEST PEM block', () => {
    expect(blocks[0].label).toBe('CERTIFICATE REQUEST');
  });

  it('has the expected top-level structure (CRI, sigAlg, signature)', () => {
    expect(csr.tag).toBe(0x10); // SEQUENCE
    expect(csr.children).toHaveLength(3);
  });

  it('declares CSR version 0 (v1)', () => {
    const versionNode = cri.children![0];
    expect(versionNode.tag).toBe(0x02); // INTEGER
    expect(versionNode.parsedValue).toMatch(/^0\b/);
  });

  it('parses the subject distinguished name', () => {
    const subject = parseDN(cri.children![1]);
    expect(formatDN(subject)).toBe(
      'CN = test.example.com, OU = TestUnit, O = TestOrg, ST = Beijing, L = Beijing, C = CN',
    );
  });

  it('carries a SubjectPublicKeyInfo with an algorithm identifier', () => {
    const spki = cri.children![2];
    const algOid = spki.children?.[0]?.children?.[0]?.parsedValue;
    expect(algOid).toBeTruthy();
    // RSA (1.2.840.113549.1.1.1) or EC (1.2.840.10045.2.1).
    expect(algOid).toMatch(/^1\.2\.840\.(113549\.1\.1\.1|10045\.2\.1)$/);
  });
});

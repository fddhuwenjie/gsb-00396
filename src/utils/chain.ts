import { parseX509, formatDN, bytesToHex, X509Fields, DistinguishedName } from './x509';
import { verifySignature, VerifyResult } from './verify';
import { lookupOID } from './oids';
import { ASN1Node } from './asn1';
import { ParsedCRL, findRevokedEntry, RevokedEntry } from './crl';

export interface ParsedCert {
  pem: string;
  der: Uint8Array;
  asn1: ASN1Node;
  fields: X509Fields;
  tbsRaw: Uint8Array;
  signatureRaw: Uint8Array;
  signatureAlgorithm: string;
  spkiRaw: Uint8Array;
  issuerRaw: string;
  subjectRaw: string;
}

export interface ChainStepResult {
  index: number;
  subject: string;
  issuer: string;
  signatureValid: boolean;
  signatureError?: string;
  nameChainValid: boolean;
  validityOk: boolean;
  validityError?: string;
  selfSigned: boolean;
  crlChecked: boolean;
  crlRevoked: boolean;
  crlRevokedEntry?: RevokedEntry;
  crlError?: string;
}

export interface ChainValidationResult {
  valid: boolean;
  chain: ParsedCert[];
  results: ChainStepResult[];
  error?: string;
}

function dnEqual(a: DistinguishedName, b: DistinguishedName): boolean {
  const keysA = Object.keys(a).sort();
  const keysB = Object.keys(b).sort();
  if (keysA.length !== keysB.length) return false;
  for (const key of keysA) {
    if (!b[key]) return false;
    if (a[key].length !== b[key].length) return false;
    const aVals = [...a[key]].sort();
    const bVals = [...b[key]].sort();
    for (let i = 0; i < aVals.length; i++) {
      if (aVals[i] !== bVals[i]) return false;
    }
  }
  return true;
}

function isSelfSigned(cert: ParsedCert): boolean {
  return dnEqual(cert.fields.issuer, cert.fields.subject);
}

export function parseCertFromDER(der: Uint8Array, pem: string): ParsedCert {
  const { fields, asn1, tbsRaw, signatureAlgorithm, signatureRaw } = parseX509(der);
  return {
    pem,
    der,
    asn1,
    fields,
    tbsRaw,
    signatureRaw,
    signatureAlgorithm,
    spkiRaw: fields.subjectPublicKeyInfo.raw,
    issuerRaw: fields.issuerRaw,
    subjectRaw: fields.subjectRaw,
  };
}

export function buildChain(leaf: ParsedCert, intermediates: ParsedCert[], roots: ParsedCert[]): ParsedCert[] {
  const chain: ParsedCert[] = [leaf];
  const allCerts = [...intermediates, ...roots];
  let current = leaf;

  const maxDepth = allCerts.length + 1;
  let depth = 0;

  while (!isSelfSigned(current) && depth < maxDepth) {
    let found = false;
    for (const cert of allCerts) {
      if (dnEqual(current.fields.issuer, cert.fields.subject) && !chain.includes(cert)) {
        chain.push(cert);
        current = cert;
        found = true;
        break;
      }
    }
    if (!found) break;
    depth++;
  }

  return chain;
}

function findCRLForIssuer(crls: ParsedCRL[], issuer: DistinguishedName): ParsedCRL | undefined {
  return crls.find((crl) => dnEqual(crl.issuer, issuer));
}

export async function validateChain(
  chain: ParsedCert[],
  crls: ParsedCRL[] = [],
): Promise<ChainValidationResult> {
  if (chain.length === 0) {
    return { valid: false, chain: [], results: [], error: 'Empty chain' };
  }

  const results: ChainStepResult[] = [];
  let allValid = true;

  for (let i = 0; i < chain.length; i++) {
    const cert = chain[i];
    const selfSigned = isSelfSigned(cert);

    const result: ChainStepResult = {
      index: i,
      subject: cert.subjectRaw,
      issuer: cert.issuerRaw,
      signatureValid: false,
      nameChainValid: true,
      validityOk: true,
      selfSigned,
      crlChecked: false,
      crlRevoked: false,
    };

    const now = new Date();
    if (now < cert.fields.validity.notBefore || now > cert.fields.validity.notAfter) {
      result.validityOk = false;
      if (now < cert.fields.validity.notBefore) {
        result.validityError = 'Certificate is not yet valid';
      } else {
        result.validityError = 'Certificate has expired';
      }
      allValid = false;
    }

    if (selfSigned) {
      const verifyResult = await verifySignature(cert.tbsRaw, cert.signatureRaw, cert.spkiRaw, cert.signatureAlgorithm);
      result.signatureValid = verifyResult.valid;
      if (!verifyResult.valid) {
        result.signatureError = verifyResult.error || 'Self-signed signature verification failed';
        allValid = false;
      }
    } else if (i + 1 < chain.length) {
      const parent = chain[i + 1];
      const nameChainOk = dnEqual(cert.fields.issuer, parent.fields.subject);
      result.nameChainValid = nameChainOk;
      if (!nameChainOk) {
        allValid = false;
      }

      const verifyResult = await verifySignature(cert.tbsRaw, cert.signatureRaw, parent.spkiRaw, cert.signatureAlgorithm);
      result.signatureValid = verifyResult.valid;
      if (!verifyResult.valid) {
        result.signatureError = verifyResult.error || 'Signature verification failed';
        allValid = false;
      }
    } else {
      result.nameChainValid = false;
      result.signatureValid = false;
      result.signatureError = 'No parent certificate found in chain';
      allValid = false;
    }

    const matchingCRL = findCRLForIssuer(crls, cert.fields.issuer);
    if (matchingCRL) {
      result.crlChecked = true;
      const serialHex = cert.fields.serialNumber.replace(/^0x/i, '').toUpperCase();
      const revoked = findRevokedEntry(matchingCRL, serialHex);
      if (revoked) {
        result.crlRevoked = true;
        result.crlRevokedEntry = revoked;
        allValid = false;
      }
    }

    results.push(result);
  }

  return { valid: allValid, chain, results };
}

import { parsePEM, parseASN1 } from './asn1';
import { parseX509, formatDN, X509Fields } from './x509';

// A flat, display-oriented summary of a certificate. This is the testable core
// behind the certificate details page: it never throws — parse failures are
// reported via the discriminated union below so the UI can show a clear error
// instead of crashing.

export interface CertExtensionSummary {
  oid: string;
  name: string;
  critical: boolean;
}

export interface CertificateSummary {
  serialNumber: string; // normalized uppercase hex, matching `openssl x509 -serial`
  subject: string;
  issuer: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyAlgorithm: string;
  publicKeyOid: string;
  keySize?: number;
  curve?: string;
  signatureAlgorithm: string;
  signatureOid: string;
  extensions: CertExtensionSummary[];
}

export type DescribeResult =
  | { ok: true; summary: CertificateSummary }
  | { ok: false; error: string };

export type ValidityStatus = 'valid' | 'not-yet-valid' | 'expired';

export interface ValidityCheck {
  status: ValidityStatus;
  /** Whole days from the verification time until the cert becomes valid (>= 0). Only meaningful when status is 'not-yet-valid'. */
  daysUntilValid: number;
  /** Whole days from the verification time until the cert expires (>= 0). Only meaningful when status is 'valid'. */
  daysUntilExpiry: number;
  /** Whole days since the cert expired (>= 0). Only meaningful when status is 'expired'. */
  daysSinceExpiry: number;
}

const MS_PER_DAY = 86_400_000;

/**
 * Normalize the parser's serial number representation to uppercase hex without
 * a `0x` prefix, so it lines up with `openssl x509 -serial` output.
 */
export function normalizeSerial(serial: string): string {
  const hexMatch = serial.match(/0x([0-9a-fA-F]+)/);
  if (hexMatch) return hexMatch[1].toUpperCase();
  return serial.trim().toUpperCase();
}

function summarizeFields(fields: X509Fields): CertificateSummary {
  return {
    serialNumber: normalizeSerial(fields.serialNumber),
    subject: formatDN(fields.subject),
    issuer: formatDN(fields.issuer),
    notBefore: fields.validity.notBefore,
    notAfter: fields.validity.notAfter,
    publicKeyAlgorithm: fields.subjectPublicKeyInfo.algorithm.name,
    publicKeyOid: fields.subjectPublicKeyInfo.algorithm.oid,
    keySize: fields.subjectPublicKeyInfo.keySize,
    curve: fields.subjectPublicKeyInfo.curve,
    signatureAlgorithm: fields.signatureAlgorithm.name,
    signatureOid: fields.signatureAlgorithm.oid,
    extensions: fields.extensions.map((ext) => ({
      oid: ext.oid,
      name: ext.name,
      critical: ext.critical,
    })),
  };
}

/**
 * Safely summarize a certificate's DER bytes. Never throws.
 */
export function describeCertificateFromDER(der: Uint8Array): DescribeResult {
  try {
    if (!der || der.length === 0) {
      return { ok: false, error: '证书内容为空' };
    }
    const { fields } = parseX509(der);
    return { ok: true, summary: summarizeFields(fields) };
  } catch (err) {
    return { ok: false, error: `无法解析证书: ${err instanceof Error ? err.message : String(err)}` };
  }
}

/**
 * Safely summarize a certificate from PEM text. Uses the same PEM/ASN.1/X.509
 * source the browser app relies on. Never throws.
 */
export function describeCertificateFromPEM(pem: string): DescribeResult {
  let blocks: { label: string; der: Uint8Array }[];
  try {
    blocks = parsePEM(pem);
  } catch (err) {
    return { ok: false, error: `无法读取 PEM: ${err instanceof Error ? err.message : String(err)}` };
  }

  const certBlock = blocks.find((b) => /CERTIFICATE$/.test(b.label)) ?? blocks[0];
  if (!certBlock) {
    return { ok: false, error: '未找到 PEM 证书块，请检查输入格式' };
  }
  return describeCertificateFromDER(certBlock.der);
}

/**
 * Compute validity status against an explicit verification time. The caller
 * always supplies the time, so results never depend on the current date.
 */
export function getValidityStatus(summary: CertificateSummary, verificationTime: Date): ValidityStatus {
  if (verificationTime < summary.notBefore) return 'not-yet-valid';
  if (verificationTime > summary.notAfter) return 'expired';
  return 'valid';
}

/**
 * Deterministic validity check against an explicit verification time. Given the
 * same certificate summary and the same verification time, this always returns
 * the same status and day counts — the computation is pure and uses absolute
 * UTC millisecond timestamps, so it is independent of the host's local time
 * zone. Day counts are whole days rounded up (a partial day still counts as one
 * remaining day).
 */
export function checkValidity(summary: CertificateSummary, verificationTime: Date): ValidityCheck {
  const now = verificationTime.getTime();
  const notBefore = summary.notBefore.getTime();
  const notAfter = summary.notAfter.getTime();
  const status = getValidityStatus(summary, verificationTime);

  return {
    status,
    daysUntilValid: status === 'not-yet-valid' ? Math.ceil((notBefore - now) / MS_PER_DAY) : 0,
    daysUntilExpiry: status === 'valid' ? Math.ceil((notAfter - now) / MS_PER_DAY) : 0,
    daysSinceExpiry: status === 'expired' ? Math.ceil((now - notAfter) / MS_PER_DAY) : 0,
  };
}

// Re-exported so the details page can decode arbitrary pasted input without
// importing parseASN1 directly.
export { parseASN1 };

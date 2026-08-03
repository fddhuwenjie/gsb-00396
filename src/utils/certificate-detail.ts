import { parsePEM } from './asn1';
import { parseX509, X509Fields, DistinguishedName, Extension, SANEntry } from './x509';

export interface CertificateDetail {
  version: number;
  serialNumber: string;
  subject: DistinguishedName;
  subjectRaw: string;
  issuer: DistinguishedName;
  issuerRaw: string;
  notBefore: Date;
  notAfter: Date;
  publicKeyAlgorithm: {
    oid: string;
    name: string;
    keySize?: number;
    curve?: string;
  };
  signatureAlgorithm: { oid: string; name: string };
  extensions: Extension[];
  san?: SANEntry[];
  keyUsage?: string[];
  extKeyUsage?: string[];
  basicConstraints?: { ca: boolean; pathLen?: number };
  ski?: string;
  aki?: string;
}

export type ParseCertificateResult =
  | { ok: true; detail: CertificateDetail }
  | { ok: false; error: string };

export type ValidityStatus = 'valid' | 'expired' | 'notYetValid';

export const MS_PER_DAY = 86_400_000;

export interface ValidityInfo {
  status: ValidityStatus;
  days: number;
}

export function getValidityStatus(
  notBefore: Date,
  notAfter: Date,
  now: Date,
): ValidityStatus {
  if (now < notBefore) return 'notYetValid';
  if (now > notAfter) return 'expired';
  return 'valid';
}

export function getValidityInfo(
  notBefore: Date,
  notAfter: Date,
  now: Date,
): ValidityInfo {
  const status = getValidityStatus(notBefore, notAfter, now);
  let days: number;
  if (status === 'notYetValid') {
    days = Math.ceil((notBefore.getTime() - now.getTime()) / MS_PER_DAY);
  } else if (status === 'expired') {
    days = Math.floor((now.getTime() - notAfter.getTime()) / MS_PER_DAY);
  } else {
    days = Math.floor((notAfter.getTime() - now.getTime()) / MS_PER_DAY);
  }
  return { status, days };
}

export function parseEvalTime(value: string): Date {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value.trim());
  if (!match) {
    throw new Error('评估时间格式无效，应为 YYYY-MM-DDTHH:mm');
  }
  const [, y, m, d, h, min] = match;
  return new Date(Date.UTC(Number(y), Number(m) - 1, Number(d), Number(h), Number(min), 0));
}

export function formatEvalInputValue(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}` +
    `T${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`
  );
}

export function isValidEvalTime(value: string): boolean {
  try {
    parseEvalTime(value);
    return true;
  } catch {
    return false;
  }
}

function toDetail(fields: X509Fields): CertificateDetail {
  return {
    version: fields.version,
    serialNumber: fields.serialNumber,
    subject: fields.subject,
    subjectRaw: fields.subjectRaw,
    issuer: fields.issuer,
    issuerRaw: fields.issuerRaw,
    notBefore: fields.validity.notBefore,
    notAfter: fields.validity.notAfter,
    publicKeyAlgorithm: {
      oid: fields.subjectPublicKeyInfo.algorithm.oid,
      name: fields.subjectPublicKeyInfo.algorithm.name,
      keySize: fields.subjectPublicKeyInfo.keySize,
      curve: fields.subjectPublicKeyInfo.curve,
    },
    signatureAlgorithm: fields.signatureAlgorithm,
    extensions: fields.extensions,
    san: fields.san,
    keyUsage: fields.keyUsage,
    extKeyUsage: fields.extKeyUsage,
    basicConstraints: fields.basicConstraints,
    ski: fields.ski,
    aki: fields.aki,
  };
}

export function parseCertificateInput(input: string): ParseCertificateResult {
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, error: '请输入 PEM 格式的证书内容' };
  }

  let blocks;
  try {
    blocks = parsePEM(trimmed);
  } catch (err) {
    return { ok: false, error: `PEM 解析失败：${(err as Error).message}` };
  }

  if (blocks.length === 0) {
    return {
      ok: false,
      error: '未找到有效的 PEM 块，请确认内容以 -----BEGIN CERTIFICATE----- 开头',
    };
  }

  const certBlocks = blocks.filter((b) => b.label === 'CERTIFICATE');
  if (certBlocks.length === 0) {
    return {
      ok: false,
      error: `PEM 块类型为 "${blocks[0].label}"，不是 CERTIFICATE`,
    };
  }

  try {
    const { fields } = parseX509(certBlocks[0].der);
    return { ok: true, detail: toDetail(fields) };
  } catch (err) {
    return { ok: false, error: `证书结构解析失败：${(err as Error).message}` };
  }
}

import { parsePEM } from './asn1';
import { parseX509, X509Fields } from './x509';

export type ParseCertResult =
  | { ok: true; fields: X509Fields }
  | { ok: false; error: string };

export type CertValidityState = 'not-yet-valid' | 'valid' | 'expired';

export interface ValidityEvaluation {
  state: CertValidityState;
  label: string;
  days: number;
  description: string;
}

const MS_PER_DAY = 24 * 60 * 60 * 1000;

function utcDayDiff(a: Date, b: Date): number {
  const aDay = Date.UTC(a.getUTCFullYear(), a.getUTCMonth(), a.getUTCDate());
  const bDay = Date.UTC(b.getUTCFullYear(), b.getUTCMonth(), b.getUTCDate());
  return Math.round((aDay - bDay) / MS_PER_DAY);
}

export function evaluateValidity(
  notBefore: Date,
  notAfter: Date,
  now: Date,
): ValidityEvaluation {
  if (now.getTime() < notBefore.getTime()) {
    const days = utcDayDiff(notBefore, now);
    return {
      state: 'not-yet-valid',
      label: '尚未生效',
      days,
      description: `距离生效还有 ${days} 天`,
    };
  }
  if (now.getTime() > notAfter.getTime()) {
    const days = utcDayDiff(now, notAfter);
    return {
      state: 'expired',
      label: '已过期',
      days,
      description: `已过期 ${days} 天`,
    };
  }
  const days = utcDayDiff(notAfter, now);
  return {
    state: 'valid',
    label: '当前有效',
    days,
    description: `距离过期还有 ${days} 天`,
  };
}

export function getValidityState(fields: X509Fields, now: Date): CertValidityState {
  return evaluateValidity(fields.validity.notBefore, fields.validity.notAfter, now).state;
}

export function tryParseCertificate(input: string): ParseCertResult {
  try {
    const trimmed = (input || '').trim();
    if (!trimmed) {
      return { ok: false, error: '证书内容为空，请粘贴 PEM 文本' };
    }

    let der: Uint8Array;
    if (trimmed.includes('-----BEGIN')) {
      const blocks = parsePEM(trimmed);
      const certBlock = blocks.find((b) => b.label === 'CERTIFICATE') || blocks[0];
      if (!certBlock || certBlock.der.length === 0) {
        return { ok: false, error: '未能在输入中找到有效的 PEM 证书块' };
      }
      if (certBlock.label !== 'CERTIFICATE') {
        return { ok: false, error: `PEM 块类型为 "${certBlock.label}"，不是 CERTIFICATE` };
      }
      der = certBlock.der;
    } else {
      const cleaned = trimmed.replace(/[\s\r\n]+/g, '');
      if (!/^[A-Za-z0-9+/=]+$/.test(cleaned)) {
        return { ok: false, error: '输入既不是 PEM 证书，也不是合法的 Base64/DER 编码' };
      }
      try {
        const binary = atob(cleaned);
        der = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
          der[i] = binary.charCodeAt(i);
        }
      } catch {
        return { ok: false, error: 'Base64 解码失败，证书内容已损坏' };
      }
    }

    if (der[0] !== 0x30) {
      return { ok: false, error: 'DER 数据不是以 SEQUENCE (0x30) 开头，证书已损坏' };
    }

    const { fields } = parseX509(der);
    return { ok: true, fields };
  } catch (err) {
    return {
      ok: false,
      error: `证书解析失败：${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

import { describe, expect, it } from 'vitest';
import { evaluateValidity, parseX509 } from '../src/utils/x509';
import { loadFixtureDer } from './helpers';

// 叶证书有效期（固定自 OpenSSL 输出）：
//   notBefore=Jun 12 08:25:26 2026 GMT
//   notAfter =Jun 12 08:25:26 2027 GMT
const { fields } = parseX509(loadFixtureDer('leaf-cert.pem'));
const { validity } = fields;
const NOT_BEFORE_MS = Date.UTC(2026, 5, 12, 8, 25, 26);
const NOT_AFTER_MS = Date.UTC(2027, 5, 12, 8, 25, 26);

describe('evaluateValidity three states', () => {
  it('not-yet-valid: before notBefore, with days until effective', () => {
    const r = evaluateValidity(validity, new Date(NOT_BEFORE_MS - 10 * 86_400_000));
    expect(r.status).toBe('not-yet-valid');
    expect(r.days).toBe(10);
  });

  it('not-yet-valid: 1 second before notBefore rounds up to 1 day', () => {
    const r = evaluateValidity(validity, new Date(NOT_BEFORE_MS - 1000));
    expect(r.status).toBe('not-yet-valid');
    expect(r.days).toBe(1);
  });

  it('valid: inside the period, with days until expiry', () => {
    const r = evaluateValidity(validity, new Date(NOT_AFTER_MS - 30 * 86_400_000));
    expect(r.status).toBe('valid');
    expect(r.days).toBe(30);
  });

  it('expired: after notAfter, with days since expiry', () => {
    const r = evaluateValidity(validity, new Date(NOT_AFTER_MS + 7 * 86_400_000));
    expect(r.status).toBe('expired');
    expect(r.days).toBe(7);
  });

  it('expired: 1 second after notAfter rounds up to 1 day', () => {
    const r = evaluateValidity(validity, new Date(NOT_AFTER_MS + 1000));
    expect(r.status).toBe('expired');
    expect(r.days).toBe(1);
  });

  it('is deterministic: same inputs produce identical results', () => {
    const at = new Date(Date.UTC(2027, 0, 1));
    const a = evaluateValidity(validity, at);
    const b = evaluateValidity(validity, new Date(at.getTime()));
    expect(a).toEqual(b);
    expect(a.status).toBe(b.status);
    expect(a.days).toBe(b.days);
  });
});

describe('evaluateValidity boundary and timezone handling', () => {
  it('validity endpoints are inclusive (X.509)', () => {
    expect(evaluateValidity(validity, new Date(NOT_BEFORE_MS)).status).toBe('valid');
    expect(evaluateValidity(validity, new Date(NOT_AFTER_MS)).status).toBe('valid');
    expect(evaluateValidity(validity, new Date(NOT_BEFORE_MS - 1)).status).toBe('not-yet-valid');
    expect(evaluateValidity(validity, new Date(NOT_AFTER_MS + 1)).status).toBe('expired');
  });

  it('same instant in different timezone representations gives same result', () => {
    // 同一时刻：UTC 与 +08:00 两种写法
    const utc = evaluateValidity(validity, new Date('2026-06-12T08:25:26Z'));
    const plus8 = evaluateValidity(validity, new Date('2026-06-12T16:25:26+08:00'));
    expect(plus8.status).toBe(utc.status);
    expect(plus8.days).toBe(utc.days);
    expect(utc.status).toBe('valid');
  });

  it('boundary instant crossing a timezone date line stays valid', () => {
    // notAfter 前一秒：UTC 是 2027-06-12，+14 时区已是 2027-06-12 深夜，结果必须一致
    const beforeUtc = evaluateValidity(validity, new Date('2027-06-12T08:25:25Z'));
    const beforePlus14 = evaluateValidity(validity, new Date('2027-06-12T22:25:25+14:00'));
    expect(beforeUtc.status).toBe('valid');
    expect(beforePlus14.status).toBe('valid');
    expect(beforePlus14.days).toBe(beforeUtc.days);

    // notAfter 后一秒：两种时区表示同样判为过期
    const afterUtc = evaluateValidity(validity, new Date('2027-06-12T08:25:27Z'));
    const afterMinus12 = evaluateValidity(validity, new Date('2027-06-11T20:25:27-12:00'));
    expect(afterUtc.status).toBe('expired');
    expect(afterMinus12.status).toBe('expired');
    expect(afterMinus12.days).toBe(afterUtc.days);
  });

  it('depends only on the absolute instant, not on Date construction', () => {
    const t = Date.UTC(2026, 11, 31, 23, 59, 59);
    const fromMs = evaluateValidity(validity, new Date(t));
    const fromIso = evaluateValidity(validity, new Date(new Date(t).toISOString()));
    expect(fromIso).toEqual(fromMs);
  });
});

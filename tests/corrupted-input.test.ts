import { beforeEach, describe, expect, it } from 'vitest';
import { parsePEM } from '../src/utils/asn1';
import { parseX509 } from '../src/utils/x509';
import { useCertificateStore } from '../src/store/certificateStore';
import { loadFixtureDer } from './helpers';

describe('corrupted input handling', () => {
  it('parseX509 throws on truncated DER', () => {
    const der = loadFixtureDer('leaf-cert.pem');
    const truncated = der.slice(0, Math.floor(der.length / 2));
    expect(() => parseX509(truncated)).toThrow();
  });

  it('parseX509 throws on garbage bytes', () => {
    const garbage = new Uint8Array([0xff, 0xff, 0xff, 0xff, 0x00, 0x01]);
    expect(() => parseX509(garbage)).toThrow();
  });

  it('parseX509 throws on non-certificate SEQUENCE', () => {
    // 空 SEQUENCE 是合法 DER 但缺少 TBS Certificate
    expect(() => parseX509(new Uint8Array([0x30, 0x00]))).toThrow(/no TBS Certificate/);
  });

  it('parsePEM throws on invalid base64 body', () => {
    const pem = '-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----';
    expect(() => parsePEM(pem)).toThrow();
  });

  it('parsePEM returns empty array for text without PEM blocks', () => {
    expect(parsePEM('just some random text')).toEqual([]);
  });
});

describe('store error path on corrupted input', () => {
  beforeEach(() => {
    useCertificateStore.getState().clearAll();
  });

  it('sets a clear error for non-PEM text without crashing', () => {
    useCertificateStore.getState().setLeafCertFromPEM('this is not a certificate');
    const state = useCertificateStore.getState();
    expect(state.leafCert).toBeNull();
    expect(state.error).toBe('未能解析证书，请检查 PEM 格式');
  });

  it('sets a clear error for PEM with truncated DER body', () => {
    const der = loadFixtureDer('leaf-cert.pem');
    const truncated = der.slice(0, Math.floor(der.length / 2));
    const b64 = Buffer.from(truncated).toString('base64');
    const pem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;
    useCertificateStore.getState().setLeafCertFromPEM(pem);
    const state = useCertificateStore.getState();
    expect(state.leafCert).toBeNull();
    expect(state.error).toBe('未能解析证书，请检查 PEM 格式');
  });

  it('recovers from a previous error when a valid certificate is loaded', () => {
    const store = useCertificateStore.getState();
    store.setLeafCertFromPEM('garbage');
    expect(useCertificateStore.getState().error).not.toBeNull();

    const der = loadFixtureDer('leaf-cert.pem');
    const b64 = Buffer.from(der).toString('base64');
    const pem = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----`;
    useCertificateStore.getState().setLeafCertFromPEM(pem);
    const state = useCertificateStore.getState();
    expect(state.error).toBeNull();
    expect(state.leafCert).not.toBeNull();
    expect(state.leafCert?.fields.subject['2.5.4.3']).toEqual(['test.example.com']);
  });
});

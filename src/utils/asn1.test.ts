import { describe, it, expect } from 'vitest';
import { parseLength, parsePEM, parseASN1 } from './asn1';
import { loadFixture } from '../test/fixtures';

describe('parseLength', () => {
  it('parses short form length (single byte, < 0x80)', () => {
    const buf = new Uint8Array([0x00]);
    expect(parseLength(buf, 0)).toEqual({ length: 0, consumed: 1 });

    const buf2 = new Uint8Array([0x7f]);
    expect(parseLength(buf2, 0)).toEqual({ length: 0x7f, consumed: 1 });
  });

  it('parses long form length with one following byte', () => {
    const buf = new Uint8Array([0x81, 0x80]);
    expect(parseLength(buf, 0)).toEqual({ length: 0x80, consumed: 2 });

    const buf2 = new Uint8Array([0x81, 0xff]);
    expect(parseLength(buf2, 0)).toEqual({ length: 0xff, consumed: 2 });
  });

  it('parses long form length with two following bytes', () => {
    const buf = new Uint8Array([0x82, 0x01, 0x00]);
    expect(parseLength(buf, 0)).toEqual({ length: 256, consumed: 3 });

    const buf2 = new Uint8Array([0x82, 0x12, 0x34]);
    expect(parseLength(buf2, 0)).toEqual({ length: 0x1234, consumed: 3 });
  });

  it('parses long form length with four following bytes', () => {
    const buf = new Uint8Array([0x84, 0x00, 0x01, 0x00, 0x00]);
    expect(parseLength(buf, 0)).toEqual({ length: 65536, consumed: 5 });
  });

  it('reads from the given offset', () => {
    const buf = new Uint8Array([0xaa, 0xbb, 0x05]);
    expect(parseLength(buf, 2)).toEqual({ length: 5, consumed: 1 });
  });

  it('throws on indefinite length (0x80) which is forbidden in DER', () => {
    const buf = new Uint8Array([0x80]);
    expect(() => parseLength(buf, 0)).toThrow(/Indefinite/);
  });

  it('throws when buffer ends before length bytes', () => {
    const buf = new Uint8Array([0x82, 0x01]);
    expect(() => parseLength(buf, 0)).toThrow(/Unexpected end/);
  });

  it('throws when offset is past the end of the buffer', () => {
    const buf = new Uint8Array([0x01]);
    expect(() => parseLength(buf, 5)).toThrow(/Unexpected end/);
  });
});

describe('parsePEM', () => {
  it('extracts label and DER bytes from a PEM certificate', () => {
    const pem = loadFixture('root-cert.pem');
    const results = parsePEM(pem);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('CERTIFICATE');
    expect(results[0].der).toBeInstanceOf(Uint8Array);
    expect(results[0].der[0]).toBe(0x30);
  });

  it('extracts a CERTIFICATE REQUEST', () => {
    const pem = loadFixture('leaf-csr.pem');
    const results = parsePEM(pem);
    expect(results).toHaveLength(1);
    expect(results[0].label).toBe('CERTIFICATE REQUEST');
    expect(results[0].der[0]).toBe(0x30);
  });
});

describe('parseASN1', () => {
  it('parses the root certificate as a constructed SEQUENCE', () => {
    const pem = loadFixture('root-cert.pem');
    const der = parsePEM(pem)[0].der;
    const node = parseASN1(der, 0);
    expect(node.tag).toBe(0x10);
    expect(node.constructed).toBe(true);
    expect(node.children).toBeDefined();
    expect(node.children!.length).toBeGreaterThanOrEqual(3);
  });
});

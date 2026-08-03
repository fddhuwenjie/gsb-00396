import { describe, it, expect } from 'vitest';
import { parseLength, parsePEM, parseASN1 } from '../src/utils/asn1';
import { loadFixture, loadFixtureDER } from './helpers';

describe('ASN.1 length parsing', () => {
  it('parses short-form length (< 0x80)', () => {
    const buf = new Uint8Array([0x05]);
    expect(parseLength(buf, 0)).toEqual({ length: 5, consumed: 1 });
  });

  it('parses short-form length 0', () => {
    const buf = new Uint8Array([0x00]);
    expect(parseLength(buf, 0)).toEqual({ length: 0, consumed: 1 });
  });

  it('parses long-form length with one byte (128)', () => {
    const buf = new Uint8Array([0x81, 0x80]);
    expect(parseLength(buf, 0)).toEqual({ length: 128, consumed: 2 });
  });

  it('parses long-form length with two bytes (256)', () => {
    const buf = new Uint8Array([0x82, 0x01, 0x00]);
    expect(parseLength(buf, 0)).toEqual({ length: 256, consumed: 3 });
  });

  it('parses long-form length with two bytes (0xffff)', () => {
    const buf = new Uint8Array([0x82, 0xff, 0xff]);
    expect(parseLength(buf, 0)).toEqual({ length: 0xffff, consumed: 3 });
  });

  it('rejects indefinite length (0x80) as invalid DER', () => {
    const buf = new Uint8Array([0x80]);
    expect(() => parseLength(buf, 0)).toThrow(/Indefinite length/);
  });

  it('throws when buffer ends before length bytes', () => {
    const buf = new Uint8Array([0x82, 0x01]);
    expect(() => parseLength(buf, 0)).toThrow(/Unexpected end/);
  });

  it('respects the offset argument', () => {
    const buf = new Uint8Array([0xff, 0xff, 0x07]);
    expect(parseLength(buf, 2)).toEqual({ length: 7, consumed: 1 });
  });
});

describe('PEM parsing', () => {
  it('extracts label and DER bytes from a certificate PEM', () => {
    const pem = loadFixture('root-cert.pem');
    const blocks = parsePEM(pem);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].label).toBe('CERTIFICATE');
    expect(blocks[0].der).toBeInstanceOf(Uint8Array);
    expect(blocks[0].der[0]).toBe(0x30);
    expect(blocks[0].der.length).toBeGreaterThan(100);
  });

  it('extracts label from a CSR PEM', () => {
    const pem = loadFixture('leaf-csr.pem');
    const blocks = parsePEM(pem);
    expect(blocks[0].label).toBe('CERTIFICATE REQUEST');
    expect(blocks[0].der[0]).toBe(0x30);
  });

  it('returns an empty array for non-PEM input', () => {
    expect(parsePEM('not a pem')).toEqual([]);
  });
});

describe('ASN.1 structure parsing', () => {
  it('parses a root certificate as a constructed SEQUENCE', () => {
    const der = loadFixtureDER('root-cert.pem');
    const node = parseASN1(der, 0);
    expect(node.tag).toBe(0x10);
    expect(node.tagClass).toBe('universal');
    expect(node.constructed).toBe(true);
    expect(node.children).toBeDefined();
    expect(node.children!.length).toBe(3);
    expect(node.headerLength + node.length).toBe(der.length);
  });

  it('reports header and value offsets consistent with the buffer', () => {
    const der = loadFixtureDER('root-cert.pem');
    const node = parseASN1(der, 0);
    expect(node.valueOffset).toBe(node.offset + node.headerLength);
    expect(node.valueOffset + node.length).toBe(der.length);
  });
});

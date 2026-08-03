import { describe, expect, it } from 'vitest';
import { parseASN1 } from '../src/utils/asn1';

function tlv(tag: number, lengthBytes: number[], contentLength: number): Uint8Array {
  const buf = new Uint8Array(1 + lengthBytes.length + contentLength);
  buf[0] = tag;
  buf.set(lengthBytes, 1);
  return buf;
}

describe('ASN.1 length parsing', () => {
  it('parses short-form length (< 128)', () => {
    const node = parseASN1(new Uint8Array([0x02, 0x01, 0x05]), 0);
    expect(node.tag).toBe(0x02);
    expect(node.length).toBe(1);
    expect(node.headerLength).toBe(2);
    expect(node.valueOffset).toBe(2);
    expect(node.rawValue).toEqual(new Uint8Array([0x05]));
  });

  it('parses long-form length with 1 length byte', () => {
    const node = parseASN1(tlv(0x04, [0x81, 0x80], 128), 0);
    expect(node.length).toBe(128);
    expect(node.headerLength).toBe(3);
    expect(node.rawValue.length).toBe(128);
  });

  it('parses long-form length with 2 length bytes', () => {
    const node = parseASN1(tlv(0x04, [0x82, 0x01, 0x00], 256), 0);
    expect(node.length).toBe(256);
    expect(node.headerLength).toBe(4);
    expect(node.rawValue.length).toBe(256);
  });

  it('parses long-form length with 3 length bytes', () => {
    const node = parseASN1(tlv(0x04, [0x83, 0x01, 0x00, 0x00], 65536), 0);
    expect(node.length).toBe(65536);
    expect(node.headerLength).toBe(5);
    expect(node.rawValue.length).toBe(65536);
  });

  it('rejects indefinite length (not valid in DER)', () => {
    expect(() => parseASN1(new Uint8Array([0x04, 0x80, 0x00, 0x00]), 0)).toThrow(
      /Indefinite length/,
    );
  });

  it('rejects truncated length bytes', () => {
    expect(() => parseASN1(new Uint8Array([0x04, 0x82, 0x01]), 0)).toThrow();
  });

  it('rejects content shorter than declared length', () => {
    expect(() => parseASN1(new Uint8Array([0x04, 0x05, 0x01, 0x02]), 0)).toThrow(
      /exceeds buffer/,
    );
  });
});

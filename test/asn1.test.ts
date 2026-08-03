import { describe, it, expect } from 'vitest';
import { parseASN1 } from '@/utils/asn1';

// These tests exercise DER length decoding through the public parseASN1 entry
// point. They build OCTET STRING TLVs by hand so the length encoding under test
// is unambiguous, covering short form, the 0x81/0x82 long forms, and the
// error paths the parser must reject.

function octetString(contentLength: number): Uint8Array {
  const content = new Uint8Array(contentLength).fill(0x41);
  let lengthBytes: number[];
  if (contentLength < 0x80) {
    lengthBytes = [contentLength];
  } else if (contentLength < 0x100) {
    lengthBytes = [0x81, contentLength];
  } else {
    lengthBytes = [0x82, (contentLength >> 8) & 0xff, contentLength & 0xff];
  }
  return new Uint8Array([0x04, ...lengthBytes, ...content]);
}

describe('ASN.1 length parsing', () => {
  it('decodes short-form lengths (< 0x80)', () => {
    const node = parseASN1(octetString(5));
    expect(node.tag).toBe(0x04);
    expect(node.length).toBe(5);
    expect(node.headerLength).toBe(2); // tag + single length byte
    expect(node.rawValue).toHaveLength(5);
  });

  it('decodes the short-form boundary length of 0x7f', () => {
    const node = parseASN1(octetString(0x7f));
    expect(node.length).toBe(0x7f);
    expect(node.headerLength).toBe(2);
  });

  it('decodes one-byte long-form lengths (0x81)', () => {
    const node = parseASN1(octetString(0x80));
    expect(node.length).toBe(0x80);
    expect(node.headerLength).toBe(3); // tag + 0x81 + one length byte
    expect(node.rawValue).toHaveLength(0x80);
  });

  it('decodes two-byte long-form lengths (0x82)', () => {
    const node = parseASN1(octetString(0x1a4));
    expect(node.length).toBe(0x1a4);
    expect(node.headerLength).toBe(4); // tag + 0x82 + two length bytes
    expect(node.rawValue).toHaveLength(0x1a4);
  });

  it('rejects indefinite-length encoding (0x80), which is invalid in DER', () => {
    // 0x04 0x80 ... : indefinite length is forbidden in DER.
    expect(() => parseASN1(new Uint8Array([0x04, 0x80, 0x00, 0x00]))).toThrow(
      /indefinite length/i,
    );
  });

  it('rejects a declared length that runs past the buffer', () => {
    // Claims 10 content bytes but only supplies 2.
    expect(() => parseASN1(new Uint8Array([0x04, 0x0a, 0x41, 0x41]))).toThrow(
      /exceeds buffer/i,
    );
  });

  it('rejects truncated long-form length bytes', () => {
    // 0x82 promises two length bytes but none follow.
    expect(() => parseASN1(new Uint8Array([0x04, 0x82]))).toThrow(
      /end of data/i,
    );
  });
});

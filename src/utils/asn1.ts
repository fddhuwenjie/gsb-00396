export interface ASN1Node {
  tag: number;
  tagClass: 'universal' | 'application' | 'context' | 'private';
  constructed: boolean;
  length: number;
  headerLength: number;
  valueOffset: number;
  rawValue: Uint8Array;
  children?: ASN1Node[];
  parsedValue?: string;
  offset: number;
}

const TAG_NAMES: Record<number, string> = {
  0x01: 'BOOLEAN',
  0x02: 'INTEGER',
  0x03: 'BIT STRING',
  0x04: 'OCTET STRING',
  0x05: 'NULL',
  0x06: 'OBJECT IDENTIFIER',
  0x07: 'ObjectDescriptor',
  0x08: 'EXTERNAL',
  0x09: 'REAL',
  0x0a: 'ENUMERATED',
  0x0b: 'EMBEDDED PDV',
  0x0c: 'UTF8String',
  0x0d: 'RELATIVE-OID',
  0x10: 'SEQUENCE',
  0x11: 'SET',
  0x12: 'NumericString',
  0x13: 'PrintableString',
  0x14: 'T61String',
  0x15: 'VideotexString',
  0x16: 'IA5String',
  0x17: 'UTCTime',
  0x18: 'GeneralizedTime',
  0x19: 'GraphicString',
  0x1a: 'VisibleString',
  0x1b: 'GeneralString',
  0x1c: 'UniversalString',
  0x1e: 'BMPString',
  0x1f: 'last',
};

export function getTagName(node: ASN1Node): string {
  if (node.tagClass === 'universal') {
    const name = TAG_NAMES[node.tag];
    if (name) return name;
    return `UNIVERSAL ${node.tag}`;
  }
  if (node.tagClass === 'context') {
    return `[${node.tag}]${node.constructed ? ' CONSTRUCTED' : ''}`;
  }
  if (node.tagClass === 'application') {
    return `APPLICATION [${node.tag}]`;
  }
  return `PRIVATE [${node.tag}]`;
}

function parseLength(buf: Uint8Array, offset: number): { length: number; consumed: number } {
  if (offset >= buf.length) throw new Error('Unexpected end of data at length parsing');
  const first = buf[offset];
  if (first < 0x80) {
    return { length: first, consumed: 1 };
  }
  const numBytes = first & 0x7f;
  if (numBytes === 0) {
    throw new Error('Indefinite length not supported in DER');
  }
  if (offset + 1 + numBytes > buf.length) throw new Error('Unexpected end of data at length bytes');
  let length = 0;
  for (let i = 0; i < numBytes; i++) {
    length = (length << 8) | buf[offset + 1 + i];
  }
  return { length, consumed: 1 + numBytes };
}

function parseOID(buf: Uint8Array): string {
  if (buf.length === 0) return '';
  const components: number[] = [];
  let first = buf[0];
  components.push(Math.floor(first / 40));
  components.push(first % 40);
  let i = 1;
  while (i < buf.length) {
    let value = 0;
    let byte: number;
    do {
      byte = buf[i++];
      value = (value << 7) | (byte & 0x7f);
    } while (byte & 0x80);
    components.push(value);
  }
  return components.join('.');
}

function parseInteger(buf: Uint8Array): string {
  if (buf.length === 0) return '0';
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  if (buf.length <= 8) {
    let val = 0n;
    let negative = false;
    if (buf[0] & 0x80) {
      negative = true;
    }
    for (let i = 0; i < buf.length; i++) {
      val = (val << 8n) | BigInt(buf[i]);
    }
    if (negative) {
      val = val - (1n << BigInt(buf.length * 8));
    }
    return val.toString() + ' (0x' + hex + ')';
  }
  return '0x' + hex;
}

function parseBitString(buf: Uint8Array): string {
  if (buf.length === 0) return '(empty)';
  const unusedBits = buf[0];
  const data = buf.slice(1);
  let hex = '';
  for (let i = 0; i < data.length; i++) {
    hex += data[i].toString(16).padStart(2, '0');
  }
  return `(${unusedBits} unused bits) 0x${hex}`;
}

function parseTime(tag: number, buf: Uint8Array): string {
  const str = new TextDecoder().decode(buf);
  if (tag === 0x17) {
    return `UTCTime: ${str}`;
  }
  return `GeneralizedTime: ${str}`;
}

function parseStringValue(tag: number, buf: Uint8Array): string {
  if (tag === 0x1e) {
    let result = '';
    for (let i = 0; i < buf.length - 1; i += 2) {
      const code = (buf[i] << 8) | buf[i + 1];
      result += String.fromCharCode(code);
    }
    return result;
  }
  if (tag === 0x1c) {
    let result = '';
    for (let i = 0; i < buf.length - 3; i += 4) {
      const code = ((buf[i] << 24) | (buf[i + 1] << 16) | (buf[i + 2] << 8) | buf[i + 3]) >>> 0;
      result += String.fromCodePoint(code);
    }
    return result;
  }
  return new TextDecoder('utf-8', { fatal: false }).decode(buf);
}

export function parseASN1(buf: Uint8Array, startOffset: number = 0, baseOffset: number = 0): ASN1Node {
  if (buf.length === 0) throw new Error('Empty buffer');

  let offset = startOffset;
  if (offset >= buf.length) throw new Error('Unexpected end of data');

  const firstByte = buf[offset];
  const tagClass = (firstByte >> 6) & 0x03;
  const constructed = !!(firstByte & 0x20);
  let tag = firstByte & 0x1f;

  offset++;

  if (tag === 0x1f) {
    tag = 0;
    let byte: number;
    do {
      if (offset >= buf.length) throw new Error('Unexpected end of data in tag');
      byte = buf[offset++];
      tag = (tag << 7) | (byte & 0x7f);
    } while (byte & 0x80);
  }

  const { length, consumed: lengthConsumed } = parseLength(buf, offset);
  offset += lengthConsumed;

  const headerLength = offset - startOffset;
  const valueOffset = offset;

  if (offset + length > buf.length) {
    throw new Error(`Content length ${length} exceeds buffer at offset ${offset} (buffer size: ${buf.length})`);
  }

  const rawValue = buf.slice(offset, offset + length);

  const classNames: Array<ASN1Node['tagClass']> = ['universal', 'application', 'context', 'private'];
  const node: ASN1Node = {
    tag,
    tagClass: classNames[tagClass],
    constructed,
    length,
    headerLength,
    valueOffset: baseOffset + valueOffset,
    rawValue,
    offset: baseOffset + startOffset,
  };

  if (constructed) {
    node.children = [];
    let childOffset = 0;
    while (childOffset < length) {
      try {
        const child = parseASN1(rawValue, childOffset, baseOffset + valueOffset);
        node.children.push(child);
        childOffset += child.headerLength + child.length;
      } catch {
        break;
      }
    }
  } else {
    if (tagClass === 0) {
      switch (tag) {
        case 0x01:
          if (rawValue.length > 0) {
            node.parsedValue = rawValue[0] !== 0 ? 'TRUE' : 'FALSE';
          }
          break;
        case 0x02:
          node.parsedValue = parseInteger(rawValue);
          break;
        case 0x03:
          node.parsedValue = parseBitString(rawValue);
          break;
        case 0x04:
          node.parsedValue = hexDump(rawValue);
          break;
        case 0x05:
          node.parsedValue = '';
          break;
        case 0x06:
          node.parsedValue = parseOID(rawValue);
          break;
        case 0x0c:
        case 0x13:
        case 0x16:
        case 0x12:
        case 0x14:
        case 0x15:
        case 0x19:
        case 0x1a:
        case 0x1b:
          node.parsedValue = parseStringValue(tag, rawValue);
          break;
        case 0x17:
        case 0x18:
          node.parsedValue = parseTime(tag, rawValue);
          break;
        case 0x0a:
          node.parsedValue = parseInteger(rawValue);
          break;
        case 0x1e:
        case 0x1c:
          node.parsedValue = parseStringValue(tag, rawValue);
          break;
      }
    } else if (tagClass === 2) {
      if (!constructed) {
        try {
          const text = new TextDecoder('utf-8', { fatal: false }).decode(rawValue);
          const isPrintable = /^[\x20-\x7E\t\r\n]*$/.test(text);
          if (isPrintable && text.length > 0) {
            node.parsedValue = text;
          } else {
            node.parsedValue = hexDump(rawValue);
          }
        } catch {
          node.parsedValue = hexDump(rawValue);
        }
      }
    }
  }

  return node;
}

function hexDump(buf: Uint8Array): string {
  if (buf.length <= 32) {
    let hex = '';
    for (let i = 0; i < buf.length; i++) {
      hex += buf[i].toString(16).padStart(2, '0');
    }
    return hex;
  }
  let hex = '';
  for (let i = 0; i < 32; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex + '...';
}

export function parseDERMultiple(buf: Uint8Array): ASN1Node[] {
  const nodes: ASN1Node[] = [];
  let offset = 0;
  while (offset < buf.length) {
    try {
      const node = parseASN1(buf, offset);
      nodes.push(node);
      offset += node.headerLength + node.length;
    } catch {
      break;
    }
  }
  return nodes;
}

export function parsePEM(pem: string): { label: string; der: Uint8Array }[] {
  const results: { label: string; der: Uint8Array }[] = [];
  const regex = /-----BEGIN ([A-Z0-9 ]+)-----\s*([\s\S]*?)\s*-----END \1-----/g;
  let match;
  while ((match = regex.exec(pem)) !== null) {
    const label = match[1];
    const b64 = match[2].replace(/[\s\r\n]/g, '');
    const binary = atob(b64);
    const der = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      der[i] = binary.charCodeAt(i);
    }
    results.push({ label, der });
  }
  return results;
}

export function oidToString(buf: Uint8Array): string {
  return parseOID(buf);
}

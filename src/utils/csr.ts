export type KeyAlgorithmType = 'RSA-2048' | 'RSA-4096' | 'ECDSA-P256' | 'ECDSA-P384';

export interface SubjectFields {
  CN?: string;
  O?: string;
  OU?: string;
  C?: string;
  ST?: string;
  L?: string;
  E?: string;
}

export interface SANField {
  type: 'DNS' | 'IP' | 'email' | 'URI';
  value: string;
}

export interface CSRResult {
  csrPEM: string;
  privateKeyPEM: string;
  publicKeyPEM: string;
}

const OID_MAP: Record<string, string> = {
  CN: '2.5.4.3',
  O: '2.5.4.10',
  OU: '2.5.4.11',
  C: '2.5.4.6',
  ST: '2.5.4.8',
  L: '2.5.4.7',
  E: '1.2.840.113549.1.9.1',
};

function encodeOID(oidStr: string): Uint8Array {
  const parts = oidStr.split('.').map(Number);
  const bytes: number[] = [];

  bytes.push(parts[0] * 40 + parts[1]);

  for (let i = 2; i < parts.length; i++) {
    let value = parts[i];
    const temp: number[] = [];
    do {
      temp.push(value & 0x7f);
      value >>= 7;
    } while (value > 0);
    for (let j = temp.length - 1; j >= 0; j--) {
      bytes.push(j === 0 ? temp[j] : temp[j] | 0x80);
    }
  }

  return new Uint8Array(bytes);
}

function encodeLength(length: number): Uint8Array {
  if (length < 0x80) {
    return new Uint8Array([length]);
  }
  const bytes: number[] = [];
  let len = length;
  while (len > 0) {
    bytes.unshift(len & 0xff);
    len >>= 8;
  }
  return new Uint8Array([0x80 | bytes.length, ...bytes]);
}

function encodeTLV(tag: number, value: Uint8Array): Uint8Array {
  const length = encodeLength(value.length);
  const result = new Uint8Array(1 + length.length + value.length);
  result[0] = tag;
  result.set(length, 1);
  result.set(value, 1 + length.length);
  return result;
}

function encodeSequence(children: Uint8Array[]): Uint8Array {
  const totalLen = children.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const child of children) {
    result.set(child, offset);
    offset += child.length;
  }
  return encodeTLV(0x30, result);
}

function encodeSet(children: Uint8Array[]): Uint8Array {
  const totalLen = children.reduce((sum, c) => sum + c.length, 0);
  const result = new Uint8Array(totalLen);
  let offset = 0;
  for (const child of children) {
    result.set(child, offset);
    offset += child.length;
  }
  return encodeTLV(0x31, result);
}

function encodeInteger(value: number | bigint): Uint8Array {
  let bigVal: bigint;
  if (typeof value === 'number') {
    bigVal = BigInt(value);
  } else {
    bigVal = value;
  }

  if (bigVal === 0n) {
    return encodeTLV(0x02, new Uint8Array([0]));
  }

  const bytes: number[] = [];
  let val = bigVal;
  while (val > 0n) {
    bytes.unshift(Number(val & 0xffn));
    val >>= 8n;
  }

  if (bytes[0] & 0x80) {
    bytes.unshift(0);
  }

  return encodeTLV(0x02, new Uint8Array(bytes));
}

function encodeString(str: string, tag: number = 0x0c): Uint8Array {
  const encoder = new TextEncoder();
  const utf8Bytes = encoder.encode(str);

  if (tag === 0x13) {
    const asciiStr = Array.from(str)
      .map((c) => (c.charCodeAt(0) < 128 ? c : '?'))
      .join('');
    const asciiBytes = encoder.encode(asciiStr);
    return encodeTLV(tag, asciiBytes);
  }

  return encodeTLV(tag, utf8Bytes);
}

function encodeBitString(data: Uint8Array, unusedBits: number = 0): Uint8Array {
  const content = new Uint8Array([unusedBits, ...data]);
  return encodeTLV(0x03, content);
}

function encodeOIDTLV(oidStr: string): Uint8Array {
  return encodeTLV(0x06, encodeOID(oidStr));
}

function encodeNull(): Uint8Array {
  return encodeTLV(0x05, new Uint8Array(0));
}

function encodeContextSpecific(tag: number, data: Uint8Array, constructed: boolean = true): Uint8Array {
  const tagByte = 0xa0 | (constructed ? 0x20 : 0x00) | tag;
  const length = encodeLength(data.length);
  const result = new Uint8Array(1 + length.length + data.length);
  result[0] = tagByte;
  result.set(length, 1);
  result.set(data, 1 + length.length);
  return result;
}

function encodeDN(subject: SubjectFields): Uint8Array {
  const fieldOrder: (keyof SubjectFields)[] = ['CN', 'OU', 'O', 'L', 'ST', 'C', 'E'];
  const rdns: Uint8Array[] = [];

  for (const field of fieldOrder) {
    const value = subject[field];
    if (!value) continue;

    const oid = OID_MAP[field];
    if (!oid) continue;

    const stringTag = field === 'E' ? 0x16 : field === 'C' ? 0x13 : 0x0c;
    const rdn = encodeSequence([encodeOIDTLV(oid), encodeString(value, stringTag)]);
    rdns.push(encodeSet([rdn]));
  }

  return encodeSequence(rdns);
}

function ipToBytes(ip: string): Uint8Array {
  const v4 = ip.split('.');
  if (v4.length === 4) {
    return new Uint8Array(v4.map((x) => parseInt(x, 10)));
  }
  const v6 = ip.split(':');
  const result = new Uint8Array(16);
  if (v6.length <= 8) {
    for (let i = 0; i < v6.length; i++) {
      const val = parseInt(v6[i] || '0', 16);
      result[i * 2] = (val >> 8) & 0xff;
      result[i * 2 + 1] = val & 0xff;
    }
  }
  return result;
}

function encodeSAN(sans: SANField[]): Uint8Array {
  const entries: Uint8Array[] = [];

  for (const san of sans) {
    let tag: number;
    let data: Uint8Array;
    const encoder = new TextEncoder();

    switch (san.type) {
      case 'DNS':
        tag = 0x82;
        data = encoder.encode(san.value);
        break;
      case 'email':
        tag = 0x81;
        data = encoder.encode(san.value);
        break;
      case 'URI':
        tag = 0x86;
        data = encoder.encode(san.value);
        break;
      case 'IP':
        tag = 0x87;
        data = ipToBytes(san.value);
        break;
      default:
        continue;
    }

    const length = encodeLength(data.length);
    const entry = new Uint8Array(1 + length.length + data.length);
    entry[0] = tag;
    entry.set(length, 1);
    entry.set(data, 1 + length.length);
    entries.push(entry);
  }

  const totalLen = entries.reduce((sum, e) => sum + e.length, 0);
  const content = new Uint8Array(totalLen);
  let offset = 0;
  for (const e of entries) {
    content.set(e, offset);
    offset += e.length;
  }
  return encodeTLV(0x30, content);
}

function encodeExtensionRequest(sans: SANField[]): Uint8Array {
  const extSeq: Uint8Array[] = [];

  if (sans.length > 0) {
    const sanEncoded = encodeSAN(sans);
    const sanOID = encodeOIDTLV('2.5.29.17');
    const extValue = encodeTLV(0x04, new Uint8Array(sanEncoded));
    extSeq.push(encodeSequence([sanOID, extValue]));
  }

  const extensions = encodeSequence(extSeq);
  const extRequestOID = encodeOIDTLV('1.2.840.113549.1.9.14');
  const extSet = encodeSet([extensions]);

  return encodeSequence([extRequestOID, extSet]);
}

export interface KeyPairResult {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  spkiDer: Uint8Array;
  pkcs8Der: Uint8Array;
  algOID: string;
  sigAlgOID: string;
  signAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;
}

async function generateKeyPair(algo: KeyAlgorithmType): Promise<KeyPairResult> {
  let keyGenParams: RsaHashedKeyGenParams | EcKeyGenParams;
  let algOID: string;
  let sigAlgOID: string;
  let signAlgorithm: AlgorithmIdentifier | RsaPssParams | EcdsaParams;

  if (algo === 'RSA-2048') {
    keyGenParams = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 2048,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    };
    algOID = '1.2.840.113549.1.1.1';
    sigAlgOID = '1.2.840.113549.1.1.11';
    signAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
  } else if (algo === 'RSA-4096') {
    keyGenParams = {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: 4096,
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: 'SHA-256',
    };
    algOID = '1.2.840.113549.1.1.1';
    sigAlgOID = '1.2.840.113549.1.1.11';
    signAlgorithm = { name: 'RSASSA-PKCS1-v1_5' };
  } else if (algo === 'ECDSA-P256') {
    keyGenParams = {
      name: 'ECDSA',
      namedCurve: 'P-256',
    };
    algOID = '1.2.840.10045.2.1';
    sigAlgOID = '1.2.840.10045.4.3.2';
    signAlgorithm = { name: 'ECDSA', hash: 'SHA-256' };
  } else {
    keyGenParams = {
      name: 'ECDSA',
      namedCurve: 'P-384',
    };
    algOID = '1.2.840.10045.2.1';
    sigAlgOID = '1.2.840.10045.4.3.3';
    signAlgorithm = { name: 'ECDSA', hash: 'SHA-384' };
  }

  const keyPair = await crypto.subtle.generateKey(
    keyGenParams,
    true,
    ['sign', 'verify'],
  );

  const spkiDer = new Uint8Array(await crypto.subtle.exportKey('spki', keyPair.publicKey));
  const pkcs8Der = new Uint8Array(await crypto.subtle.exportKey('pkcs8', keyPair.privateKey));

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    spkiDer,
    pkcs8Der,
    algOID,
    sigAlgOID,
    signAlgorithm,
  };
}

function buildAlgorithmIdentifier(algOID: string, curveOID?: string): Uint8Array {
  const oid = encodeOIDTLV(algOID);
  if (curveOID) {
    const params = encodeOIDTLV(curveOID);
    return encodeSequence([oid, params]);
  }
  return encodeSequence([oid, encodeNull()]);
}

function buildSigAlgIdentifier(sigAlgOID: string): Uint8Array {
  const oid = encodeOIDTLV(sigAlgOID);
  return encodeSequence([oid, encodeNull()]);
}

function buildCertificationRequestInfo(
  subject: SubjectFields,
  spkiDer: Uint8Array,
  algOID: string,
  algo: KeyAlgorithmType,
  sans: SANField[],
): Uint8Array {
  const version = encodeInteger(0);
  const subjectEncoded = encodeDN(subject);

  let spkiSeq: Uint8Array;
  if (algo.startsWith('RSA')) {
    const algId = buildAlgorithmIdentifier(algOID);
    const spki = parseSPKIBitString(spkiDer);
    spkiSeq = encodeSequence([algId, spki]);
  } else {
    const curveOID = algo === 'ECDSA-P256' ? '1.2.840.10045.3.1.7' : '1.3.132.0.34';
    const algId = buildAlgorithmIdentifier(algOID, curveOID);
    const spki = parseSPKIBitString(spkiDer);
    spkiSeq = encodeSequence([algId, spki]);
  }

  const attrs: Uint8Array[] = [];
  if (sans.length > 0) {
    attrs.push(encodeExtensionRequest(sans));
  }

  let content: Uint8Array[];
  if (attrs.length > 0) {
    const totalLen = attrs.reduce((sum, a) => sum + a.length, 0);
    const attrData = new Uint8Array(totalLen);
    let offset = 0;
    for (const a of attrs) {
      attrData.set(a, offset);
      offset += a.length;
    }
    const attributes = encodeContextSpecific(0, attrData, true);
    content = [version, subjectEncoded, spkiSeq, attributes];
  } else {
    content = [version, subjectEncoded, spkiSeq];
  }

  return encodeSequence(content);
}

function parseSPKIBitString(spkiDer: Uint8Array): Uint8Array {
  let offset = 0;
  if (spkiDer[offset] !== 0x30) throw new Error('Invalid SPKI');
  offset++;

  let len = spkiDer[offset++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    offset += numBytes;
  }

  if (spkiDer[offset] !== 0x30) throw new Error('Invalid SPKI algId');
  offset++;
  len = spkiDer[offset++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    for (let i = 0; i < numBytes; i++) len = (len << 8) | spkiDer[offset++];
  }
  offset += len;

  if (spkiDer[offset] !== 0x03) throw new Error('Invalid SPKI bit string');
  offset++;
  len = spkiDer[offset++];
  if (len & 0x80) {
    const numBytes = len & 0x7f;
    let l = 0;
    for (let i = 0; i < numBytes; i++) l = (l << 8) | spkiDer[offset++];
    len = l;
  }

  return encodeBitString(spkiDer.slice(offset + 1, offset + len), spkiDer[offset]);
}

function concatToDER(signature: Uint8Array, keySize: number): Uint8Array {
  const byteLen = Math.ceil(keySize / 8);
  const r = trimInteger(signature.slice(0, byteLen));
  const s = trimInteger(signature.slice(byteLen, byteLen * 2));

  const rEncoded = encodeTLV(0x02, r);
  const sEncoded = encodeTLV(0x02, s);

  const content = new Uint8Array(rEncoded.length + sEncoded.length);
  content.set(rEncoded, 0);
  content.set(sEncoded, rEncoded.length);

  return encodeTLV(0x30, content);
}

function trimInteger(data: Uint8Array): Uint8Array {
  let start = 0;
  while (start < data.length - 1 && data[start] === 0) {
    start++;
  }
  if (data[start] & 0x80) {
    const result = new Uint8Array(data.length - start + 1);
    result[0] = 0;
    result.set(data.slice(start), 1);
    return result;
  }
  return data.slice(start);
}

function derToPEM(der: Uint8Array, label: string): string {
  let binary = '';
  for (let i = 0; i < der.length; i++) {
    binary += String.fromCharCode(der[i]);
  }
  const b64 = btoa(binary);
  const lines: string[] = [];
  for (let i = 0; i < b64.length; i += 64) {
    lines.push(b64.slice(i, i + 64));
  }
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----`;
}

export async function generateCSR(
  subject: SubjectFields,
  sans: SANField[],
  algo: KeyAlgorithmType,
): Promise<CSRResult> {
  const keyResult = await generateKeyPair(algo);

  const cri = buildCertificationRequestInfo(
    subject,
    keyResult.spkiDer,
    keyResult.algOID,
    algo,
    sans,
  );

  const sigAlg = buildSigAlgIdentifier(keyResult.sigAlgOID);

  const signatureRaw = new Uint8Array(
    await crypto.subtle.sign(keyResult.signAlgorithm, keyResult.privateKey, cri),
  );

  let signatureDER: Uint8Array;
  if (algo.startsWith('ECDSA')) {
    const keySize = algo === 'ECDSA-P256' ? 256 : 384;
    signatureDER = concatToDER(signatureRaw, keySize);
  } else {
    signatureDER = signatureRaw;
  }

  const signatureBitString = encodeBitString(signatureDER);

  const csrDERData = new Uint8Array(cri.length + sigAlg.length + signatureBitString.length);
  let offset = 0;
  csrDERData.set(cri, offset);
  offset += cri.length;
  csrDERData.set(sigAlg, offset);
  offset += sigAlg.length;
  csrDERData.set(signatureBitString, offset);

  const csrDER = encodeTLV(0x30, csrDERData);

  return {
    csrPEM: derToPEM(csrDER, 'CERTIFICATE REQUEST'),
    privateKeyPEM: derToPEM(keyResult.pkcs8Der, 'PRIVATE KEY'),
    publicKeyPEM: derToPEM(keyResult.spkiDer, 'PUBLIC KEY'),
  };
}

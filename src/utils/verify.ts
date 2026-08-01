import { parseASN1 } from './asn1';

export interface VerifyResult {
  valid: boolean;
  algorithm: string;
  error?: string;
}

export interface AlgorithmParams {
  name: string;
  hash: AlgorithmIdentifier;
}

function getAlgorithmParams(sigAlgOid: string): AlgorithmParams | null {
  switch (sigAlgOid) {
    case '1.2.840.113549.1.1.11':
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-256' } };
    case '1.2.840.113549.1.1.12':
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-384' } };
    case '1.2.840.113549.1.1.13':
      return { name: 'RSASSA-PKCS1-v1_5', hash: { name: 'SHA-512' } };
    case '1.2.840.10045.4.3.2':
      return { name: 'ECDSA', hash: { name: 'SHA-256' } };
    case '1.2.840.10045.4.3.3':
      return { name: 'ECDSA', hash: { name: 'SHA-384' } };
    case '1.2.840.10045.4.3.4':
      return { name: 'ECDSA', hash: { name: 'SHA-512' } };
    default:
      return null;
  }
}

function getECNamedCurve(spkiRaw: Uint8Array): string | null {
  try {
    const spki = parseASN1(spkiRaw, 0);
    const algId = spki.children?.[0];
    const curveOid = algId?.children?.[1]?.parsedValue;
    if (!curveOid) return null;
    if (curveOid === '1.2.840.10045.3.1.7') return 'P-256';
    if (curveOid === '1.3.132.0.34') return 'P-384';
    if (curveOid === '1.3.132.0.35') return 'P-521';
  } catch {
  }
  return null;
}

function derToConcat(signature: Uint8Array, keySize: number): Uint8Array {
  let offset = 0;
  if (signature[offset++] !== 0x30) throw new Error('Invalid DER signature');
  let seqLen = signature[offset++];
  if (seqLen & 0x80) {
    const numBytes = seqLen & 0x7f;
    seqLen = 0;
    for (let i = 0; i < numBytes; i++) {
      seqLen = (seqLen << 8) | signature[offset++];
    }
  }

  if (signature[offset++] !== 0x02) throw new Error('Invalid DER signature: expected INTEGER');
  let rLen = signature[offset++];
  if (rLen & 0x80) {
    const numBytes = rLen & 0x7f;
    rLen = 0;
    for (let i = 0; i < numBytes; i++) {
      rLen = (rLen << 8) | signature[offset++];
    }
  }
  const rData = signature.slice(offset, offset + rLen);
  offset += rLen;

  if (signature[offset++] !== 0x02) throw new Error('Invalid DER signature: expected second INTEGER');
  let sLen = signature[offset++];
  if (sLen & 0x80) {
    const numBytes = sLen & 0x7f;
    sLen = 0;
    for (let i = 0; i < numBytes; i++) {
      sLen = (sLen << 8) | signature[offset++];
    }
  }
  const sData = signature.slice(offset, offset + sLen);

  const byteLen = Math.ceil(keySize / 8);
  const r = trimOrPad(rData, byteLen);
  const s = trimOrPad(sData, byteLen);

  const result = new Uint8Array(byteLen * 2);
  result.set(r, 0);
  result.set(s, byteLen);
  return result;
}

function trimOrPad(data: Uint8Array, targetLen: number): Uint8Array {
  const result = new Uint8Array(targetLen);
  let srcStart = 0;
  if (data.length > targetLen && data[0] === 0) {
    srcStart = 1;
  }
  const srcLen = data.length - srcStart;
  const dstStart = targetLen - srcLen;
  if (dstStart >= 0) {
    result.set(data.slice(srcStart), dstStart);
  } else {
    result.set(data.slice(srcStart, srcStart + targetLen), 0);
  }
  return result;
}

export async function verifySignature(
  tbsRaw: Uint8Array,
  signatureRaw: Uint8Array,
  spkiRaw: Uint8Array,
  sigAlgOid: string,
): Promise<VerifyResult> {
  const algo = getAlgorithmParams(sigAlgOid);
  if (!algo) {
    return { valid: false, algorithm: sigAlgOid, error: `Unsupported signature algorithm: ${sigAlgOid}` };
  }

  try {
    let keyAlgorithm: RsaHashedImportParams | EcKeyImportParams;
    let sigData = signatureRaw;

    if (algo.name === 'RSASSA-PKCS1-v1_5') {
      keyAlgorithm = { name: algo.name, hash: algo.hash };
    } else if (algo.name === 'ECDSA') {
      const curve = getECNamedCurve(spkiRaw);
      if (!curve) {
        return { valid: false, algorithm: algo.name, error: 'Failed to detect EC curve from SPKI' };
      }
      keyAlgorithm = { name: 'ECDSA', namedCurve: curve };
      const keySize = curve === 'P-256' ? 256 : curve === 'P-384' ? 384 : 521;
      sigData = derToConcat(signatureRaw, keySize);
    } else {
      return { valid: false, algorithm: algo.name, error: `Unsupported algorithm: ${algo.name}` };
    }

    const key = await crypto.subtle.importKey(
      'spki',
      spkiRaw,
      keyAlgorithm,
      false,
      ['verify'],
    );

    const verifyAlgorithm = algo.name === 'ECDSA'
      ? { name: 'ECDSA', hash: algo.hash }
      : keyAlgorithm;

    const valid = await crypto.subtle.verify(
      verifyAlgorithm,
      key,
      sigData,
      tbsRaw,
    );

    return { valid, algorithm: algo.name };
  } catch (err) {
    return { valid: false, algorithm: algo.name, error: String(err) };
  }
}

export { getAlgorithmParams };

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const leafPath = path.join(__dirname, 'leaf-cert.pem');
const pem = fs.readFileSync(leafPath, 'utf8');

const b64 = pem.replace(/-----BEGIN [A-Z ]+-----/g, '').replace(/-----END [A-Z ]+-----/g, '').replace(/\s+/g, '');
const binary = Buffer.from(b64, 'base64');
const der = new Uint8Array(binary);

// Parse outer SEQUENCE to find the signature BIT STRING
// We'll parse manually: find 3rd child of outer SEQUENCE
function parseTLV(buf, offset) {
  const firstByte = buf[offset];
  let tag = firstByte & 0x1f;
  let o = offset + 1;
  if (tag === 0x1f) {
    tag = 0;
    let b;
    do {
      b = buf[o++];
      tag = (tag << 7) | (b & 0x7f);
    } while (b & 0x80);
  }
  const lenFirst = buf[o];
  let length = 0;
  if (lenFirst < 0x80) {
    length = lenFirst;
    o++;
  } else {
    const numBytes = lenFirst & 0x7f;
    for (let i = 0; i < numBytes; i++) {
      length = (length << 8) | buf[o + 1 + i];
    }
    o += 1 + numBytes;
  }
  return { tag, length, valueOffset: o, headerLength: o - offset, totalLength: (o - offset) + length };
}

// Outer SEQUENCE starts at offset 0
let offset = 0;
const outer = parseTLV(der, offset);
offset = outer.valueOffset;

// Skip TBSCertificate (1st child)
const tbs = parseTLV(der, offset);
offset += tbs.totalLength;

// Skip SignatureAlgorithm (2nd child)
const sigAlg = parseTLV(der, offset);
offset += sigAlg.totalLength;

// SignatureValue (3rd child) is BIT STRING
const sigValue = parseTLV(der, offset);
// sigValue.valueOffset points to the BIT STRING value (1st byte = unused bits)
const sigDataOffset = sigValue.valueOffset + 1; // skip unused bits byte
const sigDataLength = sigValue.length - 1; // actual signature length

console.log('Signature data starts at offset:', sigDataOffset, 'length:', sigDataLength);

// Tamper with the middle byte of the signature
const tampered = new Uint8Array(der);
const tamperOffset = sigDataOffset + Math.floor(sigDataLength / 2);
const originalByte = tampered[tamperOffset];
tampered[tamperOffset] = tampered[tamperOffset] ^ 0xFF;

console.log('Tampered byte at offset:', tamperOffset);
console.log('Original byte:', originalByte.toString(16).padStart(2, '0'));
console.log('Tampered byte:', tampered[tamperOffset].toString(16).padStart(2, '0'));

// Convert back to PEM
const tamperedB64 = Buffer.from(tampered).toString('base64');
const lines = [];
for (let i = 0; i < tamperedB64.length; i += 64) {
  lines.push(tamperedB64.slice(i, i + 64));
}

const tamperedPem = `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;

const outPath = path.join(__dirname, 'tampered-leaf.pem');
fs.writeFileSync(outPath, tamperedPem);
console.log('Tampered cert written to:', outPath);

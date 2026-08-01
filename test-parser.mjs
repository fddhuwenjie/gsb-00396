
import { readFileSync } from 'fs';
import { parsePEM } from './src/utils/asn1.ts';
import { parseX509, formatDN } from './src/utils/x509.ts';
import { formatOpenSSL } from './src/utils/openssl-format.ts';
import { parseCertFromDER } from './src/utils/chain.ts';

const pem = readFileSync('./test-certs/leaf-cert.pem', 'utf8');
const pemResults = parsePEM(pem);
const der = pemResults[0].der;

const { fields, asn1, tbsRaw, signatureAlgorithm, signatureRaw } = parseX509(der);

console.log('=== X.509 Fields ===');
console.log('Version:', fields.version);
console.log('Serial Number:', fields.serialNumber);
console.log('Signature Algorithm:', fields.signatureAlgorithm.name, fields.signatureAlgorithm.oid);
console.log('Issuer:', formatDN(fields.issuer));
console.log('Subject:', formatDN(fields.subject));
console.log('Not Before:', fields.validity.notBefore.toISOString());
console.log('Not After:', fields.validity.notAfter.toISOString());
console.log('Public Key Algorithm:', fields.subjectPublicKeyInfo.algorithm.name);
console.log('Key Size:', fields.subjectPublicKeyInfo.keySize);
console.log('Curve:', fields.subjectPublicKeyInfo.curve);

console.log('\n=== Extensions ===');
for (const ext of fields.extensions) {
  console.log(`- ${ext.name} (${ext.oid}) ${ext.critical ? '[critical]' : ''}`);
}

console.log('\n=== SAN ===');
if (fields.san) {
  for (const entry of fields.san) {
    console.log(`  ${entry.type}: ${entry.value}`);
  }
}

console.log('\n=== Key Usage ===');
if (fields.keyUsage) {
  console.log('  ', fields.keyUsage.join(', '));
}

console.log('\n=== Extended Key Usage ===');
if (fields.extKeyUsage) {
  for (const eku of fields.extKeyUsage) {
    console.log('  ', eku);
  }
}

console.log('\n=== SKI ===');
console.log('  ', fields.ski);

console.log('\n=== AKI ===');
console.log('  ', fields.aki);

console.log('\n=== Basic Constraints ===');
console.log('  ', fields.basicConstraints);

console.log('\n=== OpenSSL Format Output (first 60 lines) ===');
const opensslOut = formatOpenSSL(fields, signatureRaw, signatureAlgorithm);
const lines = opensslOut.split('\n').slice(0, 60);
console.log(lines.join('\n'));

console.log('\n=== Signature info ===');
console.log('Algorithm:', signatureAlgorithm);
console.log('Signature length:', signatureRaw.length, 'bytes');
console.log('TBS length:', tbsRaw.length, 'bytes');

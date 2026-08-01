import { X509Fields, DistinguishedName, formatDN, bytesToHex } from './x509';
import { lookupOID } from './oids';

function formatSerialNumber(serial: string): string {
  let hex = '';
  const match = serial.match(/0x([0-9a-fA-F]+)/);
  if (match) {
    hex = match[1].toUpperCase();
  } else {
    const numMatch = serial.match(/^(-?\d+)/);
    if (numMatch) {
      let n = BigInt(numMatch[1]);
      if (n < 0n) {
        n = n + (1n << 64n);
      }
      hex = n.toString(16).toUpperCase();
    }
  }
  if (hex.length % 2 === 1) hex = '0' + hex;
  const pairs = hex.match(/.{1,2}/g) || [];
  return pairs.join(':');
}

function formatDNOpenSSL(dn: DistinguishedName): string {
  const parts: string[] = [];
  const order = ['2.5.4.6', '2.5.4.8', '2.5.4.7', '2.5.4.10', '2.5.4.11', '2.5.4.3', '2.5.4.5', '2.5.4.42', '2.5.4.4', '1.3.6.1.4.1.311.60.2.1.3'];
  const shortNames: Record<string, string> = {
    '2.5.4.6': 'C',
    '2.5.4.8': 'ST',
    '2.5.4.7': 'L',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
    '2.5.4.3': 'CN',
    '2.5.4.5': 'serialNumber',
    '2.5.4.42': 'GN',
    '2.5.4.4': 'SN',
    '1.3.6.1.4.1.311.60.2.1.3': 'jurisdictionC',
  };
  for (const oid of order) {
    if (dn[oid]) {
      for (const val of dn[oid]) {
        parts.push(`${shortNames[oid] || lookupOID(oid)}=${val}`);
      }
    }
  }
  for (const oid of Object.keys(dn)) {
    if (order.includes(oid)) continue;
    for (const val of dn[oid]) {
      parts.push(`${shortNames[oid] || lookupOID(oid)}=${val}`);
    }
  }
  return parts.join(', ');
}

function formatHexWithColons(buf: Uint8Array): string {
  return Array.from(buf)
    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
    .join(':');
}

function formatDate(d: Date): string {
  const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  const pad = (n: number) => n.toString().padStart(2, '0');
  return `${months[d.getUTCMonth()]} ${pad(d.getUTCDate())} ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} ${d.getUTCFullYear()} GMT`;
}

function formatHexWithColonsAndWrap(buf: Uint8Array, indent: string, bytesPerLine: number = 16): string {
  const lines: string[] = [];
  for (let i = 0; i < buf.length; i += bytesPerLine) {
    const chunk = buf.slice(i, Math.min(i + bytesPerLine, buf.length));
    const hex = Array.from(chunk)
      .map(b => b.toString(16).padStart(2, '0').toUpperCase())
      .join(':');
    lines.push(`${indent}${hex}${i + bytesPerLine < buf.length ? ':' : ''}`);
  }
  return lines.join('\n');
}

function hexToBytes(hex: string): Uint8Array {
  const clean = hex.replace(/[^0-9a-fA-F]/g, '');
  const bytes: number[] = [];
  for (let i = 0; i < clean.length; i += 2) {
    bytes.push(parseInt(clean.substr(i, 2), 16));
  }
  return new Uint8Array(bytes);
}

export function formatOpenSSL(fields: X509Fields, signatureRaw: Uint8Array, signatureAlgorithm: string): string {
  const lines: string[] = [];

  lines.push('Certificate:');
  lines.push('    Data:');
  lines.push(`        Version: ${fields.version} (0x${(fields.version - 1).toString(16)})`);
  lines.push('        Serial Number:');
  const serialHex = formatSerialNumber(fields.serialNumber);
  lines.push(`            ${serialHex}`);
  lines.push(`    Signature Algorithm: ${lookupOID(fields.signatureAlgorithm.oid)}`);
  lines.push(`        Issuer: ${formatDNOpenSSL(fields.issuer)}`);
  lines.push('        Validity');
  lines.push(`            Not Before: ${formatDate(fields.validity.notBefore)}`);
  lines.push(`            Not After : ${formatDate(fields.validity.notAfter)}`);
  lines.push(`        Subject: ${formatDNOpenSSL(fields.subject)}`);

  lines.push('        Subject Public Key Info:');
  lines.push(`            Public Key Algorithm: ${fields.subjectPublicKeyInfo.algorithm.name}`);
  if (fields.subjectPublicKeyInfo.algorithm.oid === '1.2.840.113549.1.1.1') {
    lines.push(`                Public-Key: (${fields.subjectPublicKeyInfo.keySize || 'unknown'} bit)`);
    if (fields.subjectPublicKeyInfo.rsaModulus) {
      lines.push('                Modulus:');
      lines.push(formatHexWithColonsAndWrap(fields.subjectPublicKeyInfo.rsaModulus, '                    ', 16));
    }
    if (fields.subjectPublicKeyInfo.rsaExponent !== undefined) {
      const exp = fields.subjectPublicKeyInfo.rsaExponent;
      lines.push(`                Exponent: ${exp.toString()} (0x${exp.toString(16)})`);
    }
  } else if (fields.subjectPublicKeyInfo.algorithm.oid === '1.2.840.10045.2.1') {
    lines.push(`                Public-Key: (${fields.subjectPublicKeyInfo.keySize || 'unknown'} bit)`);
    if (fields.subjectPublicKeyInfo.curve) {
      lines.push(`                NIST CURVE: ${fields.subjectPublicKeyInfo.curve}`);
    }
  }

  const x509v3Names: Record<string, string> = {
    'basicConstraints': 'X509v3 Basic Constraints',
    'keyUsage': 'X509v3 Key Usage',
    'extKeyUsage': 'X509v3 Extended Key Usage',
    'subjectAltName': 'X509v3 Subject Alternative Name',
    'issuerAltName': 'X509v3 Issuer Alternative Name',
    'subjectKeyIdentifier': 'X509v3 Subject Key Identifier',
    'authorityKeyIdentifier': 'X509v3 Authority Key Identifier',
    'cRLDistributionPoints': 'X509v3 CRL Distribution Points',
    'certificatePolicies': 'X509v3 Certificate Policies',
    'nameConstraints': 'X509v3 Name Constraints',
    'policyMappings': 'X509v3 Policy Mappings',
    'policyConstraints': 'X509v3 Policy Constraints',
    'subjectDirectoryAttributes': 'X509v3 Subject Directory Attributes',
    'freshestCRL': 'X509v3 Freshest CRL',
    'inhibitAnyPolicy': 'X509v3 Inhibit Any-Policy',
    'authorityInfoAccess': 'Authority Information Access',
    'subjectInfoAccess': 'Subject Information Access',
  };

  if (fields.extensions.length > 0) {
    lines.push('        X509v3 extensions:');
    for (const ext of fields.extensions) {
      const criticalMark = ext.critical ? ' critical' : '';
      const displayName = x509v3Names[ext.name] || ext.name;
      lines.push(`            ${displayName}:${criticalMark}`);

      if (ext.oid === '2.5.29.19' && ext.parsed) {
        const bc = ext.parsed as { ca: boolean; pathLen?: number };
        lines.push(`                CA:${bc.ca ? 'TRUE' : 'FALSE'}`);
        if (bc.pathLen !== undefined) {
          lines.push(`                Path Len: ${bc.pathLen}`);
        }
      } else if (ext.oid === '2.5.29.15' && fields.keyUsage) {
        lines.push(`                ${fields.keyUsage.join(', ')}`);
      } else if (ext.oid === '2.5.29.37' && fields.extKeyUsage) {
        const ekuNames: Record<string, string> = {
          'serverAuth (1.3.6.1.5.5.7.3.1)': 'TLS Web Server Authentication',
          'clientAuth (1.3.6.1.5.5.7.3.2)': 'TLS Web Client Authentication',
          'codeSigning (1.3.6.1.5.5.7.3.3)': 'Code Signing',
          'emailProtection (1.3.6.1.5.5.7.3.4)': 'E-mail Protection',
          'timeStamping (1.3.6.1.5.5.7.3.8)': 'Time Stamping',
          'OCSPSigning (1.3.6.1.5.5.7.3.9)': 'OCSP Signing',
          '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
          '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
          '1.3.6.1.5.5.7.3.3': 'Code Signing',
          '1.3.6.1.5.5.7.3.4': 'E-mail Protection',
          '1.3.6.1.5.5.7.3.8': 'Time Stamping',
          '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
        };
        const formatted = fields.extKeyUsage.map(e => ekuNames[e] || e).join(', ');
        lines.push(`                ${formatted}`);
      } else if (ext.oid === '2.5.29.17' && fields.san) {
        const sanStr = fields.san.map(entry => {
          if (entry.type === 'DNS') return `DNS:${entry.value}`;
          if (entry.type === 'IP') return `IP Address:${entry.value}`;
          if (entry.type === 'email') return `email:${entry.value}`;
          if (entry.type === 'URI') return `URI:${entry.value}`;
          return `${entry.type}:${entry.value}`;
        }).join(', ');
        lines.push(`                ${sanStr}`);
      } else if (ext.oid === '2.5.29.35' && fields.aki) {
        const akiBytes = hexToBytes(fields.aki);
        const akiFormatted = formatHexWithColons(akiBytes);
        lines.push(`                ${akiFormatted}`);
      } else if (ext.oid === '2.5.29.14' && fields.ski) {
        const skiBytes = hexToBytes(fields.ski);
        const skiFormatted = formatHexWithColons(skiBytes);
        lines.push(`                ${skiFormatted}`);
      } else if (ext.oid === '2.5.29.31' && fields.crlDP) {
        for (const dp of fields.crlDP) {
          lines.push('                Full Name:');
          lines.push(`                  URI:${dp}`);
        }
      } else if (ext.oid === '1.3.6.1.5.5.7.1.1' && ext.parsed) {
        const aia = ext.parsed as { entries?: { method: string; location: string }[] };
        if (aia.entries) {
          for (const entry of aia.entries) {
            lines.push(`                ${entry.method}`);
            lines.push(`                 * URI:${entry.location}`);
          }
        }
      } else {
        const hexStr = ext.value;
        if (hexStr.length > 0 && /^[0-9a-fA-F]+$/.test(hexStr)) {
          const buf = hexToBytes(hexStr);
          lines.push(formatHexWithColonsAndWrap(buf, '                ', 16));
        } else {
          lines.push(`                ${ext.value}`);
        }
      }
    }
  }

  lines.push(`    Signature Algorithm: ${lookupOID(signatureAlgorithm)}`);
  lines.push('    Signature Value:');
  lines.push(formatHexWithColonsAndWrap(signatureRaw, '         ', 18));

  return lines.join('\n');
}

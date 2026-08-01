import { ASN1Node, oidToString, parseASN1 } from './asn1';
import { lookupOID, oidToLongName } from './oids';

export interface DistinguishedName {
  [oid: string]: string[];
}

export interface Extension {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
  parsed?: Record<string, unknown>;
}

export interface SANEntry {
  type: string;
  value: string;
}

export interface X509Fields {
  version: number;
  serialNumber: string;
  signatureAlgorithm: { oid: string; name: string };
  issuer: DistinguishedName;
  issuerRaw: string;
  validity: { notBefore: Date; notAfter: Date };
  subject: DistinguishedName;
  subjectRaw: string;
  subjectPublicKeyInfo: {
    algorithm: { oid: string; name: string };
    curve?: string;
    keySize?: number;
    raw: Uint8Array;
    rsaModulus?: Uint8Array;
    rsaExponent?: bigint;
  };
  extensions: Extension[];
  san?: SANEntry[];
  keyUsage?: string[];
  extKeyUsage?: string[];
  aki?: string;
  ski?: string;
  crlDP?: string[];
  basicConstraints?: { ca: boolean; pathLen?: number };
}

function getChild(node: ASN1Node, ...path: number[]): ASN1Node | undefined {
  let current: ASN1Node | undefined = node;
  for (const idx of path) {
    if (!current?.children) return undefined;
    current = current.children[idx];
  }
  return current;
}

function parseDN(node: ASN1Node): DistinguishedName {
  const result: DistinguishedName = {};
  if (!node.children) return result;
  for (const set of node.children) {
    if (!set.children) continue;
    for (const seq of set.children) {
      if (!seq.children || seq.children.length < 2) continue;
      const oidNode = seq.children[0];
      const valNode = seq.children[1];
      if (oidNode.parsedValue) {
        const oid = oidNode.parsedValue;
        const value = valNode.parsedValue || bytesToHex(valNode.rawValue);
        if (!result[oid]) result[oid] = [];
        result[oid].push(value);
      }
    }
  }
  return result;
}

function formatDN(dn: DistinguishedName): string {
  const parts: string[] = [];
  const order = ['2.5.4.3', '2.5.4.11', '2.5.4.10', '2.5.4.8', '2.5.4.7', '2.5.4.6', '2.5.4.5', '2.5.4.42', '2.5.4.4', '1.3.6.1.4.1.311.60.2.1.3'];
  for (const oid of order) {
    if (dn[oid]) {
      for (const val of dn[oid]) {
        parts.push(`${oidToLongName(oid)} = ${val}`);
      }
    }
  }
  for (const oid of Object.keys(dn)) {
    if (order.includes(oid)) continue;
    for (const val of dn[oid]) {
      parts.push(`${oidToLongName(oid)} = ${val}`);
    }
  }
  return parts.join(', ');
}

function bytesToHex(buf: Uint8Array): string {
  let hex = '';
  for (let i = 0; i < buf.length; i++) {
    hex += buf[i].toString(16).padStart(2, '0');
  }
  return hex.toUpperCase();
}

function parseTime(node: ASN1Node): Date {
  const str = node.parsedValue || '';
  let timeStr: string;
  if (node.tag === 0x17) {
    timeStr = str.replace('UTCTime: ', '').trim();
    if (timeStr.endsWith('Z')) timeStr = timeStr.slice(0, -1);
    const year = parseInt(timeStr.substring(0, 2));
    const fullYear = year >= 50 ? 1900 + year : 2000 + year;
    const month = parseInt(timeStr.substring(2, 4)) - 1;
    const day = parseInt(timeStr.substring(4, 6));
    const hour = parseInt(timeStr.substring(6, 8) || '0');
    const min = parseInt(timeStr.substring(8, 10) || '0');
    const sec = parseInt(timeStr.substring(10, 12) || '0');
    return new Date(Date.UTC(fullYear, month, day, hour, min, sec));
  }
  timeStr = str.replace('GeneralizedTime: ', '').trim();
  if (timeStr.endsWith('Z')) timeStr = timeStr.slice(0, -1);
  const fullYear = parseInt(timeStr.substring(0, 4));
  const month = parseInt(timeStr.substring(4, 6)) - 1;
  const day = parseInt(timeStr.substring(6, 8));
  const hour = parseInt(timeStr.substring(8, 10) || '0');
  const min = parseInt(timeStr.substring(10, 12) || '0');
  const sec = parseInt(timeStr.substring(12, 14) || '0');
  return new Date(Date.UTC(fullYear, month, day, hour, min, sec));
}

function parseKeyUsage(rawBuf: Uint8Array): string[] {
  const usages: string[] = [];
  if (rawBuf.length < 2) return usages;
  const unusedBits = rawBuf[0];
  const data = rawBuf.slice(1);
  const names = ['Digital Signature', 'Non Repudiation', 'Key Encipherment',
    'Data Encipherment', 'Key Agreement', 'Certificate Sign',
    'CRL Sign', 'Encipher Only', 'Decipher Only'];
  const totalBits = data.length * 8 - unusedBits;
  for (let i = 0; i < totalBits && i < names.length; i++) {
    const byteIndex = Math.floor(i / 8);
    const bitIndex = 7 - (i % 8);
    if ((data[byteIndex] >> bitIndex) & 1) {
      usages.push(names[i]);
    }
  }
  return usages;
}

function tryDecodeString(raw: Uint8Array): string | null {
  try {
    const text = new TextDecoder('utf-8', { fatal: true }).decode(raw);
    if (/^[\x20-\x7E\t\r\n]*$/.test(text) && text.length > 0) {
      return text;
    }
  } catch {
  }
  return null;
}

function parseSAN(extValue: ASN1Node): SANEntry[] {
  const entries: SANEntry[] = [];
  if (!extValue.children) return entries;
  for (const child of extValue.children) {
    if (child.tagClass === 'context') {
      const strVal = child.parsedValue && !/^[0-9a-fA-F]+$/.test(child.parsedValue)
        ? child.parsedValue
        : (tryDecodeString(child.rawValue) || bytesToHex(child.rawValue));

      switch (child.tag) {
        case 0: // otherName
          entries.push({ type: 'otherName', value: strVal });
          break;
        case 1: // rfc822Name
          entries.push({ type: 'email', value: strVal });
          break;
        case 2: // dNSName
          entries.push({ type: 'DNS', value: strVal });
          break;
        case 3: // x400Address
          entries.push({ type: 'x400Address', value: bytesToHex(child.rawValue) });
          break;
        case 4: // directoryName
          if (child.constructed && child.children?.[0]) {
            entries.push({ type: 'DirectoryName', value: formatDN(parseDN(child.children[0])) });
          }
          break;
        case 5: // ediPartyName
          entries.push({ type: 'ediPartyName', value: bytesToHex(child.rawValue) });
          break;
        case 6: // uniformResourceIdentifier
          entries.push({ type: 'URI', value: strVal });
          break;
        case 7: { // iPAddress
          const raw = child.rawValue;
          if (raw.length === 4) {
            entries.push({ type: 'IP', value: `${raw[0]}.${raw[1]}.${raw[2]}.${raw[3]}` });
          } else if (raw.length === 16) {
            const parts: string[] = [];
            for (let i = 0; i < 16; i += 2) {
              parts.push(((raw[i] << 8) | raw[i + 1]).toString(16));
            }
            entries.push({ type: 'IP', value: parts.join(':') });
          } else {
            entries.push({ type: 'IP', value: bytesToHex(raw) });
          }
          break;
        }
        case 8: // registeredID
          entries.push({ type: 'registeredID', value: strVal });
          break;
        default:
          entries.push({ type: `[${child.tag}]`, value: strVal });
      }
    }
  }
  return entries;
}

function parseAKI(extValue: ASN1Node): string {
  if (!extValue.children) {
    return bytesToHex(extValue.rawValue);
  }
  for (const child of extValue.children) {
    if (child.tagClass === 'context' && child.tag === 0) {
      return bytesToHex(child.rawValue);
    }
  }
  return bytesToHex(extValue.rawValue);
}

function parseSKI(extValue: ASN1Node): string {
  return bytesToHex(extValue.rawValue);
}

function parseCRLDP(extValue: ASN1Node): string[] {
  const result: string[] = [];
  if (!extValue.children) return result;
  for (const dp of extValue.children) {
    if (!dp.children) continue;
    const distributionPoint = dp.children[0];
    if (!distributionPoint?.children) continue;
    for (const nameChoice of distributionPoint.children) {
      if (nameChoice.tagClass === 'context' && nameChoice.tag === 0 && nameChoice.children) {
        for (const uriSeq of nameChoice.children) {
          if (uriSeq.children) {
            for (const uri of uriSeq.children) {
              if (uri.tagClass === 'context' && uri.tag === 6) {
                result.push(uri.parsedValue || bytesToHex(uri.rawValue));
              }
            }
          }
        }
      }
    }
  }
  return result;
}

function parseEKU(extValue: ASN1Node): string[] {
  const result: string[] = [];
  if (!extValue.children) return result;
  for (const oid of extValue.children) {
    if (oid.parsedValue) {
      result.push(lookupOID(oid.parsedValue) + ' (' + oid.parsedValue + ')');
    }
  }
  return result;
}

function parseBasicConstraints(extValue: ASN1Node): { ca: boolean; pathLen?: number } {
  if (!extValue.children || extValue.children.length === 0) {
    return { ca: false };
  }
  const seq = extValue.children[0];
  let ca = false;
  let pathLen: number | undefined;
  if (seq.children) {
    if (seq.children.length >= 1 && seq.children[0].tag === 0x01) {
      ca = seq.children[0].parsedValue === 'TRUE';
    }
    if (seq.children.length >= 2 && seq.children[1].tag === 0x02) {
      const pathLenStr = seq.children[1].parsedValue || '0';
      pathLen = parseInt(pathLenStr);
    }
  }
  return { ca, pathLen };
}

function getRsaKeySize(spki: ASN1Node): number {
  const pubKey = getChild(spki, 1);
  if (!pubKey || pubKey.rawValue.length < 2) return 0;
  const unusedBits = pubKey.rawValue[0];
  const bitStringData = pubKey.rawValue.slice(1);
  try {
    const rsaKey = parseASN1(bitStringData, 0);
    const modulus = getChild(rsaKey, 0);
    if (modulus?.rawValue) {
      let len = modulus.rawValue.length;
      if (modulus.rawValue[0] === 0) len--;
      return len * 8;
    }
  } catch {
  }
  return 0;
}

export function parseX509(der: Uint8Array): { fields: X509Fields; asn1: ASN1Node; tbsRaw: Uint8Array; signatureAlgorithm: string; signatureRaw: Uint8Array } {
  const asn1 = parseASN1(der, 0);
  const tbsCert = getChild(asn1, 0);
  if (!tbsCert) throw new Error('Invalid X.509: no TBS Certificate');

  const tbsRaw = der.slice(tbsCert.offset, tbsCert.offset + tbsCert.headerLength + tbsCert.length);

  const sigAlgNode = getChild(asn1, 1);
  const sigAlgOid = sigAlgNode?.children?.[0]?.parsedValue || '';
  const sigAlgName = lookupOID(sigAlgOid);

  const sigValue = getChild(asn1, 2);
  let signatureRaw = new Uint8Array(0);
  if (sigValue?.rawValue && sigValue.rawValue.length > 0) {
    const unusedBits = sigValue.rawValue[0];
    signatureRaw = sigValue.rawValue.slice(1);
  }

  let version = 1;
  const versionNode = getChild(tbsCert, 0);
  if (versionNode?.tagClass === 'context' && versionNode.tag === 0 && versionNode.children?.[0]) {
    version = (parseInt(versionNode.children[0].parsedValue || '0')) + 1;
  }

  const serialIdx = versionNode?.tagClass === 'context' ? 1 : 0;
  const serialNode = getChild(tbsCert, serialIdx);
  const serialNumber = serialNode?.parsedValue || '';

  const tbsSigAlgIdx = serialIdx + 1;
  const tbsSigAlg = getChild(tbsCert, tbsSigAlgIdx);
  const tbsSigAlgOid = tbsSigAlg?.children?.[0]?.parsedValue || sigAlgOid;

  const issuerIdx = tbsSigAlgIdx + 1;
  const issuerNode = getChild(tbsCert, issuerIdx);
  const issuer = issuerNode ? parseDN(issuerNode) : {};
  const issuerRaw = issuerNode ? formatDN(issuer) : '';

  const validityIdx = issuerIdx + 1;
  const validityNode = getChild(tbsCert, validityIdx);
  let notBefore = new Date();
  let notAfter = new Date();
  if (validityNode?.children && validityNode.children.length >= 2) {
    notBefore = parseTime(validityNode.children[0]);
    notAfter = parseTime(validityNode.children[1]);
  }

  const subjectIdx = validityIdx + 1;
  const subjectNode = getChild(tbsCert, subjectIdx);
  const subject = subjectNode ? parseDN(subjectNode) : {};
  const subjectRaw = subjectNode ? formatDN(subject) : '';

  const spkiIdx = subjectIdx + 1;
  const spkiNode = getChild(tbsCert, spkiIdx);
  const spkiAlgOid = spkiNode?.children?.[0]?.children?.[0]?.parsedValue || '';
  const spkiAlgName = lookupOID(spkiAlgOid);
  const curveOid = spkiNode?.children?.[0]?.children?.[1]?.parsedValue || '';
  const curveName = curveOid ? lookupOID(curveOid) : undefined;
  let keySize = 0;
  if (spkiAlgOid === '1.2.840.113549.1.1.1') {
    keySize = getRsaKeySize(spkiNode!);
  } else if (curveOid === '1.2.840.10045.3.1.7') {
    keySize = 256;
  } else if (curveOid === '1.3.132.0.34') {
    keySize = 384;
  }

  const rawSPKI = spkiNode ? der.slice(spkiNode.offset, spkiNode.offset + spkiNode.headerLength + spkiNode.length) : new Uint8Array(0);

  let rsaModulus: Uint8Array | undefined;
  let rsaExponent: bigint | undefined;
  if (spkiAlgOid === '1.2.840.113549.1.1.1' && spkiNode) {
    const pubKey = getChild(spkiNode, 1);
    if (pubKey && pubKey.rawValue.length >= 2) {
      const bitStringData = pubKey.rawValue.slice(1);
      try {
        const rsaKey = parseASN1(bitStringData, 0);
        const modulusNode = getChild(rsaKey, 0);
        const exponentNode = getChild(rsaKey, 1);
        if (modulusNode?.rawValue) {
          rsaModulus = modulusNode.rawValue;
        }
        if (exponentNode?.rawValue && exponentNode.rawValue.length > 0) {
          let exp = 0n;
          for (const b of exponentNode.rawValue) {
            exp = (exp << 8n) | BigInt(b);
          }
          rsaExponent = exp;
        }
      } catch {
      }
    }
  }

  let extensions: Extension[] = [];
  let san: SANEntry[] | undefined;
  let keyUsage: string[] | undefined;
  let extKeyUsage: string[] | undefined;
  let aki: string | undefined;
  let ski: string | undefined;
  let crlDP: string[] | undefined;
  let basicConstraints: { ca: boolean; pathLen?: number } | undefined;

  if (version >= 3 && tbsCert.children) {
    for (let i = spkiIdx + 1; i < tbsCert.children.length; i++) {
      const child = tbsCert.children[i];
      if (child.tagClass === 'context' && child.tag === 3 && child.children?.[0]) {
        const extSeq = child.children[0];
        if (extSeq.children) {
          for (const ext of extSeq.children) {
            if (!ext.children || ext.children.length < 2) continue;
            const extOidNode = ext.children[0];
            const extOid = extOidNode.parsedValue || '';
            const extName = lookupOID(extOid);

            let critical = false;
            let extValueNode: ASN1Node | undefined;

            if (ext.children.length === 3) {
              critical = ext.children[1].parsedValue === 'TRUE';
              extValueNode = ext.children[2];
            } else {
              extValueNode = ext.children[1];
            }

            let parsedExtValue = extValueNode?.parsedValue || (extValueNode ? bytesToHex(extValueNode.rawValue) : '');

            const extension: Extension = {
              oid: extOid,
              name: extName,
              critical,
              value: parsedExtValue,
            };

            try {
              if (extValueNode) {
                const innerParsed = parseASN1(extValueNode.rawValue, 0);

                switch (extOid) {
                  case '2.5.29.17':
                    san = parseSAN(innerParsed);
                    extension.parsed = { entries: san };
                    break;
                  case '2.5.29.15':
                    keyUsage = parseKeyUsage(innerParsed.rawValue);
                    extension.parsed = { usages: keyUsage };
                    break;
                  case '2.5.29.37':
                    extKeyUsage = parseEKU(innerParsed);
                    extension.parsed = { usages: extKeyUsage };
                    break;
                  case '2.5.29.35':
                    aki = parseAKI(innerParsed);
                    extension.parsed = { keyIdentifier: aki };
                    break;
                  case '2.5.29.14':
                    ski = parseSKI(innerParsed);
                    extension.parsed = { keyIdentifier: ski };
                    break;
                  case '2.5.29.31':
                    crlDP = parseCRLDP(innerParsed);
                    extension.parsed = { distributionPoints: crlDP };
                    break;
                  case '2.5.29.19':
                    basicConstraints = parseBasicConstraints(innerParsed);
                    extension.parsed = { ...basicConstraints };
                    break;
                  case '1.3.6.1.5.5.7.1.1': {
                    const aiaEntries: { method: string; location: string }[] = [];
                    if (innerParsed.children) {
                      for (const seq of innerParsed.children) {
                        if (seq.children && seq.children.length >= 2) {
                          const method = seq.children[0].parsedValue || '';
                          const accessLoc = seq.children[1];
                          let location = '';
                          if (accessLoc.children) {
                            for (const c of accessLoc.children) {
                              if (c.tag === 6) {
                                location = c.parsedValue || bytesToHex(c.rawValue);
                              }
                            }
                          }
                          aiaEntries.push({ method: lookupOID(method) + ' (' + method + ')', location });
                        }
                      }
                    }
                    extension.parsed = { entries: aiaEntries };
                    break;
                  }
                }
              }
            } catch {
              // keep raw value if inner parse fails
            }

            extensions.push(extension);
          }
        }
      }
    }
  }

  const fields: X509Fields = {
    version,
    serialNumber,
    signatureAlgorithm: { oid: tbsSigAlgOid, name: lookupOID(tbsSigAlgOid) },
    issuer,
    issuerRaw,
    validity: { notBefore, notAfter },
    subject,
    subjectRaw,
    subjectPublicKeyInfo: {
      algorithm: { oid: spkiAlgOid, name: spkiAlgName },
      curve: curveName,
      keySize: keySize || undefined,
      raw: rawSPKI,
      rsaModulus,
      rsaExponent,
    },
    extensions,
    san,
    keyUsage,
    extKeyUsage,
    aki,
    ski,
    crlDP,
    basicConstraints,
  };

  return {
    fields,
    asn1,
    tbsRaw,
    signatureAlgorithm: sigAlgOid,
    signatureRaw,
  };
}

export { formatDN, bytesToHex, parseDN, parseTime };

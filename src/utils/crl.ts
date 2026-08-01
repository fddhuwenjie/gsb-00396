import { parseASN1, parsePEM, ASN1Node } from './asn1';
import { DistinguishedName, X509Fields, formatDN, bytesToHex } from './x509';
import { lookupOID } from './oids';
import { parseDN, parseTime } from './x509';

export interface RevokedEntry {
  serialNumber: string;
  revocationDate: Date;
  reason?: string;
  invalidityDate?: Date;
}

export interface ParsedCRL {
  pem: string;
  der: Uint8Array;
  issuer: DistinguishedName;
  issuerRaw: string;
  thisUpdate: Date;
  nextUpdate?: Date;
  revokedEntries: RevokedEntry[];
  signatureAlgorithm: string;
  signatureAlgorithmName: string;
  crlNumber?: string;
}

function getChild(node: ASN1Node, ...path: number[]): ASN1Node | undefined {
  let current: ASN1Node | undefined = node;
  for (const idx of path) {
    if (!current?.children) return undefined;
    current = current.children[idx];
  }
  return current;
}

const CRL_REASONS: Record<number, string> = {
  0: 'Unspecified',
  1: 'Key Compromise',
  2: 'CA Compromise',
  3: 'Affiliation Changed',
  4: 'Superseded',
  5: 'Cessation of Operation',
  6: 'Certificate Hold',
  8: 'Remove from CRL',
  9: 'Privilege Withdrawn',
  10: 'AA Compromise',
};

function parseCRLExtensions(extNode: ASN1Node): { reason?: string; invalidityDate?: Date; crlNumber?: string } {
  const result: { reason?: string; invalidityDate?: Date; crlNumber?: string } = {};
  if (!extNode.children) return result;

  for (const ext of extNode.children) {
    if (!ext.children || ext.children.length < 2) continue;
    const extOid = ext.children[0].parsedValue || '';
    const extValueNode = ext.children.length === 3 ? ext.children[2] : ext.children[1];
    if (!extValueNode) continue;

    try {
      const inner = parseASN1(extValueNode.rawValue, 0);

      if (extOid === '2.5.29.21') {
        if (inner.tag === 0x0a || inner.rawValue.length > 0) {
          let reasonCode = 0;
          if (inner.parsedValue) {
            const match = inner.parsedValue.match(/\((\d+)\)/);
            if (match) reasonCode = parseInt(match[1]);
            else {
              const hex = inner.parsedValue.replace('0x', '');
              reasonCode = parseInt(hex, 16);
            }
          } else if (inner.rawValue.length > 0) {
            reasonCode = inner.rawValue[inner.rawValue.length - 1];
          }
          result.reason = CRL_REASONS[reasonCode] || `Unknown (${reasonCode})`;
        }
      } else if (extOid === '2.5.29.24') {
        if (inner.children) {
          for (const c of inner.children) {
            if (c.tagClass === 'context' && c.tag === 0) {
              result.invalidityDate = parseTime(c);
            }
          }
        }
      } else if (extOid === '2.5.29.20') {
        result.crlNumber = bytesToHex(inner.rawValue);
      }
    } catch {
    }
  }

  return result;
}

export function parseCRLFromDER(der: Uint8Array, pem: string): ParsedCRL {
  const asn1 = parseASN1(der, 0);
  const tbsCertList = getChild(asn1, 0);
  if (!tbsCertList) throw new Error('Invalid CRL: no TBS Cert List');

  let idx = 0;

  const signatureNode = getChild(tbsCertList, idx);
  const sigAlgOid = signatureNode?.children?.[0]?.parsedValue || '';
  idx++;

  const issuerNode = getChild(tbsCertList, idx);
  const issuer = issuerNode ? parseDN(issuerNode) : {};
  const issuerRaw = issuerNode ? formatDN(issuer) : '';
  idx++;

  const thisUpdateNode = getChild(tbsCertList, idx);
  const thisUpdate = thisUpdateNode ? parseTime(thisUpdateNode) : new Date();
  idx++;

  let nextUpdate: Date | undefined;
  const nextNode = getChild(tbsCertList, idx);
  if (nextNode && (nextNode.tag === 0x17 || nextNode.tag === 0x18)) {
    nextUpdate = parseTime(nextNode);
    idx++;
  }

  const revokedEntries: RevokedEntry[] = [];
  const revokedListNode = getChild(tbsCertList, idx);
  if (revokedListNode?.children) {
    for (const entry of revokedListNode.children) {
      if (!entry.children || entry.children.length < 2) continue;

      const serialNode = entry.children[0];
      const dateNode = entry.children[1];

      const serialHex = serialNode?.parsedValue
        ? serialNode.parsedValue.replace('0x', '').toUpperCase()
        : bytesToHex(serialNode?.rawValue || new Uint8Array(0));

      const revocationDate = dateNode ? parseTime(dateNode) : new Date();

      let reason: string | undefined;
      let invalidityDate: Date | undefined;

      if (entry.children.length > 2) {
        const extNode = entry.children[2];
        if (extNode?.tagClass === 'context' && extNode.tag === 0 && extNode.children?.[0]) {
          const extResult = parseCRLExtensions(extNode.children[0]);
          reason = extResult.reason;
          invalidityDate = extResult.invalidityDate;
        }
      }

      revokedEntries.push({
        serialNumber: serialHex,
        revocationDate,
        reason,
        invalidityDate,
      });
    }
  }
  idx++;

  let crlNumber: string | undefined;
  for (let i = idx; i < (tbsCertList.children?.length || 0); i++) {
    const extContainer = tbsCertList.children?.[i];
    if (extContainer?.tagClass === 'context' && extContainer.tag === 0 && extContainer.children?.[0]) {
      const extResult = parseCRLExtensions(extContainer.children[0]);
      if (extResult.crlNumber) crlNumber = extResult.crlNumber;
    }
  }

  const sigAlgNode2 = getChild(asn1, 1);
  const sigAlgOid2 = sigAlgNode2?.children?.[0]?.parsedValue || sigAlgOid;

  return {
    pem,
    der,
    issuer,
    issuerRaw,
    thisUpdate,
    nextUpdate,
    revokedEntries,
    signatureAlgorithm: sigAlgOid2,
    signatureAlgorithmName: lookupOID(sigAlgOid2),
    crlNumber,
  };
}

export function parseCRLFromPEM(pem: string): ParsedCRL {
  const results = parsePEM(pem);
  if (results.length === 0) {
    throw new Error('No valid PEM data found');
  }
  const { der } = results[0];
  return parseCRLFromDER(der, pem);
}

export function findRevokedEntry(crl: ParsedCRL, serialNumberHex: string): RevokedEntry | undefined {
  const normalized = serialNumberHex.replace(/^0x/i, '').toUpperCase().replace(/^0+/, '');
  return crl.revokedEntries.find((entry) => {
    const entryNormalized = entry.serialNumber.replace(/^0+/, '');
    return entryNormalized === normalized || entry.serialNumber.toUpperCase() === serialNumberHex.toUpperCase();
  });
}

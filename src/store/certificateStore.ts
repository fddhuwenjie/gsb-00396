import { create } from 'zustand';
import { parsePEM, parseASN1 } from '@/utils/asn1';
import { parseX509 } from '@/utils/x509';
import {
  ParsedCert,
  buildChain,
  validateChain,
  ChainValidationResult,
  parseCertFromDER,
} from '@/utils/chain';
import { VerifyResult, verifySignature } from '@/utils/verify';
import { ParsedCRL, parseCRLFromPEM, parseCRLFromDER } from '@/utils/crl';

export type TabType = 'asn1' | 'x509' | 'chain' | 'openssl' | 'csr' | 'crl';

interface CertificateState {
  leafCert: ParsedCert | null;
  intermediateCerts: ParsedCert[];
  rootCerts: ParsedCert[];
  crls: ParsedCRL[];
  activeTab: TabType;
  chainResult: ChainValidationResult | null;
  verifyResult: VerifyResult | null;
  error: string | null;
  isVerifying: boolean;

  setActiveTab: (tab: TabType) => void;
  setLeafCertFromPEM: (pem: string) => void;
  setLeafCertFromDER: (der: Uint8Array) => void;
  addIntermediateCert: (cert: ParsedCert) => void;
  addRootCert: (cert: ParsedCert) => void;
  addCRL: (crl: ParsedCRL) => void;
  removeCRL: (index: number) => void;
  removeIntermediateCert: (index: number) => void;
  removeRootCert: (index: number) => void;
  clearAll: () => void;
  runChainValidation: () => Promise<void>;
  runSelfVerify: () => Promise<void>;
  parsePEMToCerts: (pem: string) => ParsedCert[];
  parseDERToCert: (der: Uint8Array, pem?: string) => ParsedCert | null;
  parseCRL: (pem: string) => ParsedCRL | null;
  parseCRLFromDERBytes: (der: Uint8Array, pem?: string) => ParsedCRL | null;
}

function derToPEM(der: Uint8Array, label: string = 'CERTIFICATE'): string {
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

export const useCertificateStore = create<CertificateState>((set, get) => ({
  leafCert: null,
  intermediateCerts: [],
  rootCerts: [],
  crls: [],
  activeTab: 'x509',
  chainResult: null,
  verifyResult: null,
  error: null,
  isVerifying: false,

  setActiveTab: (tab) => set({ activeTab: tab }),

  parsePEMToCerts: (pem: string): ParsedCert[] => {
    const results: ParsedCert[] = [];
    try {
      const pemCerts = parsePEM(pem);
      for (const pc of pemCerts) {
        try {
          const cert = parseCertFromDER(pc.der, pem);
          results.push(cert);
        } catch {
        }
      }
    } catch {
    }
    return results;
  },

  parseDERToCert: (der: Uint8Array, pem?: string): ParsedCert | null => {
    try {
      parseASN1(der, 0);
      const certPem = pem || derToPEM(der);
      return parseCertFromDER(der, certPem);
    } catch {
      return null;
    }
  },

  parseCRL: (pem: string): ParsedCRL | null => {
    try {
      return parseCRLFromPEM(pem);
    } catch {
      return null;
    }
  },

  parseCRLFromDERBytes: (der: Uint8Array, pem?: string): ParsedCRL | null => {
    try {
      const crlPem = pem || derToPEM(der, 'X509 CRL');
      return parseCRLFromDER(der, crlPem);
    } catch {
      return null;
    }
  },

  setLeafCertFromPEM: (pem: string) => {
    try {
      const certs = get().parsePEMToCerts(pem);
      if (certs.length > 0) {
        set({ leafCert: certs[0], error: null, chainResult: null, verifyResult: null });
      } else {
        set({ error: '未能解析证书，请检查 PEM 格式' });
      }
    } catch (err) {
      set({ error: String(err) });
    }
  },

  setLeafCertFromDER: (der: Uint8Array) => {
    try {
      const cert = get().parseDERToCert(der);
      if (cert) {
        set({ leafCert: cert, error: null, chainResult: null, verifyResult: null });
      } else {
        set({ error: '未能解析证书，请检查 DER 格式' });
      }
    } catch (err) {
      set({ error: String(err) });
    }
  },

  addIntermediateCert: (cert: ParsedCert) => {
    set((state) => ({
      intermediateCerts: [...state.intermediateCerts, cert],
      chainResult: null,
    }));
  },

  addRootCert: (cert: ParsedCert) => {
    set((state) => ({
      rootCerts: [...state.rootCerts, cert],
      chainResult: null,
    }));
  },

  addCRL: (crl: ParsedCRL) => {
    set((state) => ({
      crls: [...state.crls, crl],
      chainResult: null,
    }));
  },

  removeCRL: (index: number) => {
    set((state) => ({
      crls: state.crls.filter((_, i) => i !== index),
      chainResult: null,
    }));
  },

  removeIntermediateCert: (index: number) => {
    set((state) => ({
      intermediateCerts: state.intermediateCerts.filter((_, i) => i !== index),
      chainResult: null,
    }));
  },

  removeRootCert: (index: number) => {
    set((state) => ({
      rootCerts: state.rootCerts.filter((_, i) => i !== index),
      chainResult: null,
    }));
  },

  clearAll: () => {
    set({
      leafCert: null,
      intermediateCerts: [],
      rootCerts: [],
      crls: [],
      chainResult: null,
      verifyResult: null,
      error: null,
    });
  },

  runChainValidation: async () => {
    const { leafCert, intermediateCerts, rootCerts, crls } = get();
    if (!leafCert) {
      set({ error: '请先提供叶子证书' });
      return;
    }

    set({ isVerifying: true, error: null });

    try {
      const chain = buildChain(leafCert, intermediateCerts, rootCerts);
      const result = await validateChain(chain, crls);
      set({ chainResult: result, isVerifying: false });
    } catch (err) {
      set({ error: String(err), isVerifying: false });
    }
  },

  runSelfVerify: async () => {
    const { leafCert } = get();
    if (!leafCert) {
      set({ error: '请先提供证书' });
      return;
    }

    set({ isVerifying: true, error: null });

    try {
      const result = await verifySignature(
        leafCert.tbsRaw,
        leafCert.signatureRaw,
        leafCert.spkiRaw,
        leafCert.signatureAlgorithm,
      );
      set({ verifyResult: result, isVerifying: false });
    } catch (err) {
      set({ error: String(err), isVerifying: false });
    }
  },
}));

import { useState } from 'react';
import { Copy, Check, Terminal, FileText } from 'lucide-react';
import { useCertificateStore } from '@/store/certificateStore';
import { formatOpenSSL } from '@/utils/openssl-format';

export default function OpenSSLExport() {
  const { leafCert } = useCertificateStore();
  const [copied, setCopied] = useState(false);

  const opensslText = leafCert
    ? formatOpenSSL(leafCert.fields, leafCert.signatureRaw, leafCert.signatureAlgorithm)
    : '';

  const handleCopy = async () => {
    if (!opensslText) return;
    try {
      await navigator.clipboard.writeText(opensslText);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  };

  if (!leafCert) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500">
        <Terminal className="w-12 h-12 mb-4 opacity-30" />
        <p className="text-sm">请先加载证书以生成 OpenSSL 风格输出</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          OpenSSL 风格输出
        </h3>
        <button
          onClick={handleCopy}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-md transition-colors"
        >
          {copied ? (
            <>
              <Check className="w-3.5 h-3.5 text-emerald-400" />
              已复制
            </>
          ) : (
            <>
              <Copy className="w-3.5 h-3.5" />
              复制
            </>
          )}
        </button>
      </div>

      <div className="flex-1 overflow-auto bg-zinc-950 rounded-lg border border-zinc-800 p-4 font-mono text-xs text-zinc-300 whitespace-pre">
        {opensslText}
      </div>

      <div className="mt-3 flex items-center gap-2 text-xs text-zinc-500">
        <FileText className="w-3.5 h-3.5" />
        <span>可与 <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-zinc-400">openssl x509 -text -noout</code> 输出对比</span>
      </div>
    </div>
  );
}

import { useState, useRef, useCallback } from 'react';
import { Upload, FileText, X, Plus, AlertCircle, Copy, Check, Ban, Calendar, Hash, User } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useCertificateStore } from '@/store/certificateStore';
import { ParsedCRL, RevokedEntry } from '@/utils/crl';

export default function CRLParser() {
  const {
    crls,
    addCRL,
    removeCRL,
    parseCRL,
    parseCRLFromDERBytes,
    error,
  } = useCertificateStore();

  const [pemText, setPemText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [selectedCRL, setSelectedCRL] = useState<ParsedCRL | null>(null);
  const [copied, setCopied] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setPemText(e.target.value);
  };

  const handleParsePEM = () => {
    if (!pemText.trim()) return;
    const crl = parseCRL(pemText);
    if (crl) {
      addCRL(crl);
      setSelectedCRL(crl);
      setPemText('');
    }
  };

  const processFileContent = useCallback(
    (content: string | ArrayBuffer) => {
      if (typeof content === 'string') {
        const crl = parseCRL(content);
        if (crl) {
          addCRL(crl);
          setSelectedCRL(crl);
          return;
        }
      }

      let der: Uint8Array | null = null;
      if (typeof content === 'string') {
        try {
          const binary = atob(content.replace(/[\s\r\n]/g, ''));
          der = new Uint8Array(binary.length);
          for (let i = 0; i < binary.length; i++) {
            der[i] = binary.charCodeAt(i);
          }
        } catch {
          const encoder = new TextEncoder();
          der = encoder.encode(content);
        }
      } else if (content instanceof ArrayBuffer) {
        der = new Uint8Array(content);
        try {
          const decoder = new TextDecoder('utf-8');
          const text = decoder.decode(der, { stream: false });
          if (text.includes('-----BEGIN')) {
            const crl = parseCRL(text);
            if (crl) {
              addCRL(crl);
              setSelectedCRL(crl);
              return;
            }
          }
        } catch {
        }
      }

      if (der) {
        const crl = parseCRLFromDERBytes(der);
        if (crl) {
          addCRL(crl);
          setSelectedCRL(crl);
        }
      }
    },
    [parseCRL, parseCRLFromDERBytes, addCRL]
  );

  const handleFile = useCallback(
    (file: File) => {
      const isTextFile = /\.(pem|crl)$/i.test(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        const result = e.target?.result;
        if (result !== undefined && result !== null) {
          processFileContent(result as string | ArrayBuffer);
        }
      };
      if (isTextFile) {
        reader.readAsText(file);
      } else {
        reader.readAsArrayBuffer(file);
      }
    },
    [processFileContent]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setIsDragging(false);
      const files = e.dataTransfer.files;
      for (const file of files) {
        handleFile(file);
      }
    },
    [handleFile]
  );

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (files) {
      for (const file of files) {
        handleFile(file);
      }
    }
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
    }
  };

  const formatDate = (date: Date) => {
    return date.toLocaleString('zh-CN', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZone: 'UTC',
    }) + ' UTC';
  };

  const activeCRL = selectedCRL || crls[0] || null;

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex gap-4 flex-1 min-h-0 overflow-hidden">
        <div className="w-80 flex-shrink-0 flex flex-col gap-4 overflow-auto pr-2">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-2">
              <FileText className="w-4 h-4 text-rose-400" />
              CRL 输入
            </h3>

            <div
              className={cn(
                'border-2 border-dashed rounded-lg p-4 text-center transition-all cursor-pointer mb-3',
                isDragging
                  ? 'border-rose-500/50 bg-rose-500/5'
                  : 'border-zinc-700 hover:border-zinc-600 bg-zinc-900/30'
              )}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
              onClick={() => fileInputRef.current?.click()}
            >
              <Upload className="w-8 h-8 mx-auto mb-2 text-zinc-500" />
              <p className="text-xs text-zinc-400 mb-1">
                拖拽 .pem / .crl / .der 文件到此处
              </p>
              <p className="text-xs text-zinc-500">或点击选择文件</p>
              <input
                ref={fileInputRef}
                type="file"
                accept=".pem,.crl,.der"
                multiple
                className="hidden"
                onChange={handleFileInput}
              />
            </div>

            <textarea
              value={pemText}
              onChange={handleTextChange}
              placeholder="-----BEGIN X509 CRL-----
MIICXTCCAUUCAQEwDQYJKoZIhvc..."
              className="w-full h-32 bg-zinc-900/50 border border-zinc-700 rounded-md p-3 text-xs font-mono text-zinc-300 placeholder-zinc-600 resize-none focus:outline-none focus:border-rose-500/50 focus:ring-1 focus:ring-rose-500/20 transition-all mb-2"
              spellCheck={false}
            />
            <button
              onClick={handleParsePEM}
              disabled={!pemText.trim()}
              className={cn(
                'w-full py-2 rounded-md text-sm font-medium transition-all flex items-center justify-center gap-2',
                pemText.trim()
                  ? 'bg-rose-500 text-white hover:bg-rose-400'
                  : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
              )}
            >
              <Plus className="w-4 h-4" />
              解析 CRL
            </button>
          </div>

          {error && (
            <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-md">
              <p className="text-xs text-red-400">{error}</p>
            </div>
          )}

          <div className="flex flex-col gap-2">
            <h3 className="text-xs font-medium text-zinc-400">已加载 CRL ({crls.length})</h3>

            {crls.map((crl, i) => (
              <div
                key={i}
                onClick={() => setSelectedCRL(crl)}
                className={cn(
                  'flex items-center gap-2 px-3 py-2 rounded-md border text-xs cursor-pointer transition-all',
                  activeCRL === crl
                    ? 'bg-rose-500/10 border-rose-500/30 text-rose-400'
                    : 'bg-zinc-900/50 border-zinc-700 text-zinc-300 hover:border-zinc-600'
                )}
              >
                <Ban className="w-3.5 h-3.5 flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <span className="block truncate font-mono text-[11px]">
                    {crl.issuerRaw || 'Unknown Issuer'}
                  </span>
                  <span className="block text-[10px] text-zinc-500 mt-0.5">
                    {crl.revokedEntries.length} 条吊销记录
                  </span>
                </div>
                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    removeCRL(i);
                    if (activeCRL === crl) {
                      setSelectedCRL(null);
                    }
                  }}
                  className="text-zinc-500 hover:text-zinc-300 transition-colors"
                >
                  <X className="w-3.5 h-3.5" />
                </button>
              </div>
            ))}

            {crls.length === 0 && (
              <p className="text-xs text-zinc-600 text-center py-4">暂无 CRL</p>
            )}
          </div>
        </div>

        <div className="flex-1 flex flex-col min-w-0 overflow-auto">
          {activeCRL ? (
            <div className="space-y-4">
              <div className="bg-zinc-900/50 rounded-xl border border-zinc-800 p-4">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <AlertCircle className="w-4 h-4 text-rose-400" />
                    CRL 基本信息
                  </h3>
                  <button
                    onClick={() => copyToClipboard(activeCRL.pem)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
                  >
                    {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                    复制 PEM
                  </button>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <InfoField icon={User} label="Issuer (颁发者)" value={activeCRL.issuerRaw || '-'} multiline />
                  <InfoField icon={Hash} label="签名算法" value={activeCRL.signatureAlgorithmName || activeCRL.signatureAlgorithm} />
                  <InfoField icon={Calendar} label="This Update" value={formatDate(activeCRL.thisUpdate)} />
                  <InfoField icon={Calendar} label="Next Update" value={activeCRL.nextUpdate ? formatDate(activeCRL.nextUpdate) : '-'} />
                  {activeCRL.crlNumber && (
                    <InfoField icon={Hash} label="CRL Number" value={`0x${activeCRL.crlNumber}`} multiline />
                  )}
                  <InfoField icon={Ban} label="吊销条目数" value={`${activeCRL.revokedEntries.length} 条`} />
                </div>
              </div>

              <div className="bg-zinc-900/50 rounded-xl border border-zinc-800 overflow-hidden">
                <div className="px-4 py-3 border-b border-zinc-800 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
                    <Ban className="w-4 h-4 text-rose-400" />
                    吊销证书列表
                  </h3>
                  <span className="text-xs text-zinc-500">
                    共 {activeCRL.revokedEntries.length} 条
                  </span>
                </div>

                {activeCRL.revokedEntries.length > 0 ? (
                  <div className="overflow-auto max-h-[400px]">
                    <table className="w-full text-xs">
                      <thead className="bg-zinc-800/50 sticky top-0">
                        <tr>
                          <th className="text-left px-4 py-2 text-zinc-400 font-medium">序列号</th>
                          <th className="text-left px-4 py-2 text-zinc-400 font-medium">吊销时间</th>
                          <th className="text-left px-4 py-2 text-zinc-400 font-medium">吊销原因</th>
                        </tr>
                      </thead>
                      <tbody>
                        {activeCRL.revokedEntries.map((entry, i) => (
                          <RevokedRow key={i} entry={entry} formatDate={formatDate} />
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <div className="p-8 text-center">
                    <Ban className="w-10 h-10 mx-auto mb-3 text-zinc-600 opacity-50" />
                    <p className="text-sm text-zinc-500">此 CRL 中没有吊销的证书</p>
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-zinc-500">
              <Ban className="w-12 h-12 mb-4 opacity-30" />
              <p className="text-sm">请先加载 CRL 文件</p>
              <p className="text-xs text-zinc-600 mt-1">加载后可查看吊销证书列表并用于链验证</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

function InfoField({
  icon: Icon,
  label,
  value,
  multiline,
}: {
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  value: string;
  multiline?: boolean;
}) {
  return (
    <div>
      <label className="flex items-center gap-1.5 text-[11px] text-zinc-500 mb-1">
        <Icon className="w-3 h-3" />
        {label}
      </label>
      <div
        className={cn(
          'text-xs text-zinc-200 bg-zinc-800/50 rounded-md px-3 py-2',
          multiline ? 'font-mono break-all' : ''
        )}
      >
        {value}
      </div>
    </div>
  );
}

function RevokedRow({
  entry,
  formatDate,
}: {
  entry: RevokedEntry;
  formatDate: (d: Date) => string;
}) {
  return (
    <tr className="border-t border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
      <td className="px-4 py-2">
        <code className="text-[11px] text-amber-400 font-mono break-all">
          0x{entry.serialNumber}
        </code>
      </td>
      <td className="px-4 py-2 text-zinc-300 text-[11px] whitespace-nowrap">
        {formatDate(entry.revocationDate)}
      </td>
      <td className="px-4 py-2">
        {entry.reason ? (
          <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] bg-red-500/15 text-red-400">
            {entry.reason}
          </span>
        ) : (
          <span className="text-zinc-500 text-[11px]">-</span>
        )}
      </td>
    </tr>
  );
}

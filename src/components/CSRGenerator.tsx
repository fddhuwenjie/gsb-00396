import { useState } from 'react';
import { FileKey, Copy, Check, Download, Plus, X, AlertTriangle, Loader2, Sparkles } from 'lucide-react';
import { cn } from '@/lib/utils';
import { generateCSR, SubjectFields, SANField, KeyAlgorithmType, CSRResult } from '@/utils/csr';

const SUBJECT_FIELDS: { key: keyof SubjectFields; label: string; placeholder: string }[] = [
  { key: 'CN', label: 'Common Name (CN)', placeholder: '例如: example.com' },
  { key: 'O', label: 'Organization (O)', placeholder: '例如: Example Inc.' },
  { key: 'OU', label: 'Org Unit (OU)', placeholder: '例如: IT Department' },
  { key: 'C', label: 'Country (C)', placeholder: '例如: CN' },
  { key: 'ST', label: 'State (ST)', placeholder: '例如: Beijing' },
  { key: 'L', label: 'Locality (L)', placeholder: '例如: Beijing' },
  { key: 'E', label: 'Email (E)', placeholder: '例如: admin@example.com' },
];

const KEY_ALGORITHMS: { value: KeyAlgorithmType; label: string }[] = [
  { value: 'RSA-2048', label: 'RSA 2048-bit' },
  { value: 'RSA-4096', label: 'RSA 4096-bit' },
  { value: 'ECDSA-P256', label: 'ECDSA P-256' },
  { value: 'ECDSA-P384', label: 'ECDSA P-384' },
];

type OutputTab = 'csr' | 'private' | 'public';

export default function CSRGenerator() {
  const [subject, setSubject] = useState<SubjectFields>({});
  const [sans, setSans] = useState<SANField[]>([
    { type: 'DNS', value: '' },
  ]);
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithmType>('RSA-2048');
  const [isGenerating, setIsGenerating] = useState(false);
  const [result, setResult] = useState<CSRResult | null>(null);
  const [activeOutputTab, setActiveOutputTab] = useState<OutputTab>('csr');
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const updateSubject = (key: keyof SubjectFields, value: string) => {
    setSubject((prev) => ({ ...prev, [key]: value }));
  };

  const updateSAN = (index: number, field: 'type' | 'value', value: string) => {
    setSans((prev) =>
      prev.map((san, i) => (i === index ? { ...san, [field]: value as SANField[typeof field] } : san))
    );
  };

  const addSAN = () => {
    setSans((prev) => [...prev, { type: 'DNS', value: '' }]);
  };

  const removeSAN = (index: number) => {
    if (sans.length <= 1) return;
    setSans((prev) => prev.filter((_, i) => i !== index));
  };

  const handleGenerate = async () => {
    setError(null);
    setResult(null);

    const hasSubject = Object.values(subject).some((v) => v && v.trim());
    const hasSAN = sans.some((s) => s.value.trim());

    if (!hasSubject && !hasSAN) {
      setError('请至少填写一个 Subject 字段或添加一个 SAN');
      return;
    }

    if (!subject.CN && !sans.some((s) => s.type === 'DNS' && s.value.trim())) {
      setError('建议填写 Common Name (CN) 或添加 DNS 类型的 SAN');
    }

    const validSANs = sans.filter((s) => s.value.trim());

    setIsGenerating(true);
    try {
      const csrResult = await generateCSR(subject, validSANs, keyAlgorithm);
      setResult(csrResult);
      setActiveOutputTab('csr');
    } catch (err) {
      setError(String(err));
    } finally {
      setIsGenerating(false);
    }
  };

  const currentOutput = result
    ? activeOutputTab === 'csr'
      ? result.csrPEM
      : activeOutputTab === 'private'
      ? result.privateKeyPEM
      : result.publicKeyPEM
    : '';

  const copyOutput = async () => {
    if (!currentOutput) return;
    try {
      await navigator.clipboard.writeText(currentOutput);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
    }
  };

  const downloadOutput = () => {
    if (!result) return;
    const fileNames: Record<OutputTab, string> = {
      csr: 'certificate-request.csr.pem',
      private: 'private-key.pem',
      public: 'public-key.pem',
    };
    const labels: Record<OutputTab, string> = {
      csr: 'CERTIFICATE REQUEST',
      private: 'PRIVATE KEY',
      public: 'PUBLIC KEY',
    };
    const blob = new Blob([currentOutput], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileNames[activeOutputTab];
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="h-full flex flex-col overflow-hidden">
      <div className="flex gap-4 flex-1 min-h-0 overflow-hidden">
        <div className="w-96 flex-shrink-0 flex flex-col gap-4 overflow-auto pr-2">
          <div>
            <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-cyan-400" />
              证书签名请求 (CSR)
            </h3>

            <div className="mb-4">
              <label className="block text-[11px] text-zinc-400 mb-2">密钥算法</label>
              <div className="grid grid-cols-2 gap-2">
                {KEY_ALGORITHMS.map((alg) => (
                  <button
                    key={alg.value}
                    onClick={() => setKeyAlgorithm(alg.value)}
                    className={cn(
                      'px-3 py-2 text-xs rounded-md border transition-all text-left',
                      keyAlgorithm === alg.value
                        ? 'bg-cyan-500/10 border-cyan-500/30 text-cyan-400'
                        : 'bg-zinc-900/50 border-zinc-700 text-zinc-400 hover:border-zinc-600'
                    )}
                  >
                    {alg.label}
                  </button>
                ))}
              </div>
            </div>

            <div className="mb-4">
              <label className="block text-[11px] text-zinc-400 mb-2">Subject 字段</label>
              <div className="space-y-2">
                {SUBJECT_FIELDS.map((field) => (
                  <div key={field.key}>
                    <label className="block text-[10px] text-zinc-500 mb-1">{field.label}</label>
                    <input
                      type="text"
                      value={subject[field.key] || ''}
                      onChange={(e) => updateSubject(field.key, e.target.value)}
                      placeholder={field.placeholder}
                      className="w-full bg-zinc-900/50 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    />
                  </div>
                ))}
              </div>
            </div>

            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <label className="text-[11px] text-zinc-400">Subject Alternative Names (SAN)</label>
                <button
                  onClick={addSAN}
                  className="flex items-center gap-1 text-[10px] text-cyan-400 hover:text-cyan-300 transition-colors"
                >
                  <Plus className="w-3 h-3" />
                  添加
                </button>
              </div>
              <div className="space-y-2">
                {sans.map((san, i) => (
                  <div key={i} className="flex gap-2">
                    <select
                      value={san.type}
                      onChange={(e) => updateSAN(i, 'type', e.target.value)}
                      className="w-20 bg-zinc-900/50 border border-zinc-700 rounded-md px-2 py-2 text-xs text-zinc-200 focus:outline-none focus:border-cyan-500/50 transition-all appearance-none"
                    >
                      <option value="DNS">DNS</option>
                      <option value="IP">IP</option>
                      <option value="email">Email</option>
                      <option value="URI">URI</option>
                    </select>
                    <input
                      type="text"
                      value={san.value}
                      onChange={(e) => updateSAN(i, 'value', e.target.value)}
                      placeholder={
                        san.type === 'DNS'
                          ? 'example.com'
                          : san.type === 'IP'
                          ? '192.168.1.1'
                          : san.type === 'email'
                          ? 'admin@example.com'
                          : 'https://example.com'
                      }
                      className="flex-1 bg-zinc-900/50 border border-zinc-700 rounded-md px-3 py-2 text-xs text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                    />
                    {sans.length > 1 && (
                      <button
                        onClick={() => removeSAN(i)}
                        className="p-2 text-zinc-500 hover:text-red-400 transition-colors"
                      >
                        <X className="w-3.5 h-3.5" />
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            {error && (
              <div className="p-3 bg-amber-500/10 border border-amber-500/30 rounded-md mb-4">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-amber-400">{error}</p>
                </div>
              </div>
            )}

            <button
              onClick={handleGenerate}
              disabled={isGenerating}
              className={cn(
                'w-full py-2.5 rounded-lg text-sm font-medium transition-all flex items-center justify-center gap-2',
                !isGenerating
                  ? 'bg-cyan-500 text-zinc-900 hover:bg-cyan-400'
                  : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
              )}
            >
              {isGenerating ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <FileKey className="w-4 h-4" />
              )}
              {isGenerating ? '生成中...' : '生成密钥对和 CSR'}
            </button>
          </div>
        </div>

        <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
          {result ? (
            <div className="flex flex-col h-full">
              <div className="flex items-center gap-2 mb-3 border-b border-zinc-800 pb-3">
                {(['csr', 'private', 'public'] as OutputTab[]).map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveOutputTab(tab)}
                    className={cn(
                      'px-3 py-1.5 text-xs rounded-md transition-all',
                      activeOutputTab === tab
                        ? tab === 'csr'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                          : tab === 'private'
                          ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 border border-transparent'
                    )}
                  >
                    {tab === 'csr' ? 'CSR' : tab === 'private' ? '私钥' : '公钥'}
                  </button>
                ))}
                <div className="flex-1" />
                <button
                  onClick={copyOutput}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
                >
                  {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                  复制
                </button>
                <button
                  onClick={downloadOutput}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md bg-zinc-800 hover:bg-zinc-700 text-zinc-300 text-xs transition-colors"
                >
                  <Download className="w-3.5 h-3.5" />
                  下载
                </button>
              </div>

              <div className="flex-1 overflow-auto bg-zinc-900/50 rounded-xl border border-zinc-800 p-4">
                <pre className="text-xs font-mono text-zinc-300 whitespace-pre-wrap break-all">
                  {currentOutput}
                </pre>
              </div>

              {activeOutputTab === 'private' && (
                <div className="mt-3 p-3 bg-amber-500/10 border border-amber-500/30 rounded-md">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0 mt-0.5" />
                    <div>
                      <p className="text-xs font-medium text-amber-400">⚠️ 请妥善保管私钥</p>
                      <p className="text-[11px] text-amber-400/80 mt-0.5">
                        私钥不会被上传到任何服务器，仅生成在您的浏览器中。请立即安全保存并不要分享。
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="flex flex-col items-center justify-center h-full text-zinc-500">
              <FileKey className="w-12 h-12 mb-4 opacity-30" />
              <p className="text-sm">填写左侧表单后生成 CSR</p>
              <p className="text-xs text-zinc-600 mt-1">所有操作均在浏览器内完成，数据不会上传</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

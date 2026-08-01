import { useState, useRef, useCallback } from 'react';
import { Upload, FileText, X, Plus, Leaf, GitBranch, TreeDeciduous } from 'lucide-react';
import { cn } from '@/lib/utils';
import { useCertificateStore } from '@/store/certificateStore';
import type { ParsedCert } from '@/utils/chain';

type CertRole = 'leaf' | 'intermediate' | 'root';

export default function CertificateInput() {
  const {
    leafCert,
    intermediateCerts,
    rootCerts,
    setLeafCertFromPEM,
    setLeafCertFromDER,
    addIntermediateCert,
    addRootCert,
    removeIntermediateCert,
    removeRootCert,
    clearAll,
    parsePEMToCerts,
    parseDERToCert,
    error,
  } = useCertificateStore();

  const [pemText, setPemText] = useState('');
  const [isDragging, setIsDragging] = useState(false);
  const [selectedRole, setSelectedRole] = useState<CertRole>('leaf');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    const text = e.clipboardData.getData('text');
    if (text && text.includes('-----BEGIN')) {
      setPemText(text);
    }
  }, []);

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setPemText(e.target.value);
  };

  const handleParsePEM = () => {
    if (!pemText.trim()) return;
    const certs = parsePEMToCerts(pemText);
    if (certs.length === 0) return;

    if (selectedRole === 'leaf') {
      setLeafCertFromPEM(pemText);
    } else if (selectedRole === 'intermediate') {
      certs.forEach((c) => addIntermediateCert(c));
    } else {
      certs.forEach((c) => addRootCert(c));
    }
    setPemText('');
  };

  const processFileContent = useCallback(
    (content: string | ArrayBuffer, fileName: string) => {
      if (typeof content === 'string') {
        const certs = parsePEMToCerts(content);
        if (certs.length > 0) {
          if (selectedRole === 'leaf') {
            setLeafCertFromPEM(content);
          } else if (selectedRole === 'intermediate') {
            certs.forEach((c) => addIntermediateCert(c));
          } else {
            certs.forEach((c) => addRootCert(c));
          }
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
            const certs = parsePEMToCerts(text);
            if (certs.length > 0) {
              if (selectedRole === 'leaf') {
                setLeafCertFromPEM(text);
              } else if (selectedRole === 'intermediate') {
                certs.forEach((c) => addIntermediateCert(c));
              } else {
                certs.forEach((c) => addRootCert(c));
              }
              return;
            }
          }
        } catch {
        }
      }

      if (der) {
        const cert = parseDERToCert(der);
        if (cert) {
          if (selectedRole === 'leaf') {
            setLeafCertFromDER(der);
          } else if (selectedRole === 'intermediate') {
            addIntermediateCert(cert);
          } else {
            addRootCert(cert);
          }
        }
      }
    },
    [selectedRole, parsePEMToCerts, parseDERToCert, setLeafCertFromPEM, setLeafCertFromDER, addIntermediateCert, addRootCert]
  );

  const handleFile = useCallback(
    (file: File) => {
      const isTextFile = /\.(pem|crt|cer)$/i.test(file.name);
      const reader = new FileReader();
      reader.onload = (e) => {
        const result = e.target?.result;
        if (result !== undefined && result !== null) {
          processFileContent(result as string | ArrayBuffer, file.name);
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

  const getCertDisplayName = (cert: ParsedCert) => {
    const cn = cert.fields.subject['2.5.4.3']?.[0];
    return cn || cert.subjectRaw || 'Unknown';
  };

  return (
    <div className="flex flex-col gap-4 h-full">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-zinc-200 flex items-center gap-2">
          <FileText className="w-4 h-4 text-emerald-400" />
          证书输入
        </h2>
        <button
          onClick={clearAll}
          className="text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
        >
          清空全部
        </button>
      </div>

      <div className="flex gap-2">
        {(['leaf', 'intermediate', 'root'] as CertRole[]).map((role) => (
          <button
            key={role}
            onClick={() => setSelectedRole(role)}
            className={cn(
              'flex-1 px-3 py-2 text-xs rounded-md border transition-all flex items-center justify-center gap-1.5',
              selectedRole === role
                ? role === 'leaf'
                  ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
                  : role === 'intermediate'
                  ? 'bg-amber-500/10 border-amber-500/30 text-amber-400'
                  : 'bg-sky-500/10 border-sky-500/30 text-sky-400'
                : 'bg-zinc-800/50 border-zinc-700 text-zinc-400 hover:border-zinc-600'
            )}
          >
            {role === 'leaf' && <Leaf className="w-3.5 h-3.5" />}
            {role === 'intermediate' && <GitBranch className="w-3.5 h-3.5" />}
            {role === 'root' && <TreeDeciduous className="w-3.5 h-3.5" />}
            {role === 'leaf' ? '叶子证书' : role === 'intermediate' ? '中间证书' : '根证书'}
          </button>
        ))}
      </div>

      <div
        className={cn(
          'border-2 border-dashed rounded-lg p-4 text-center transition-all cursor-pointer',
          isDragging
            ? 'border-emerald-500/50 bg-emerald-500/5'
            : 'border-zinc-700 hover:border-zinc-600 bg-zinc-900/30'
        )}
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onClick={() => fileInputRef.current?.click()}
      >
        <Upload className="w-8 h-8 mx-auto mb-2 text-zinc-500" />
        <p className="text-xs text-zinc-400 mb-1">
          拖拽 .pem / .cer / .crt / .der 文件到此处
        </p>
        <p className="text-xs text-zinc-500">或点击选择文件</p>
        <input
          ref={fileInputRef}
          type="file"
          accept=".pem,.cer,.crt,.der"
          multiple
          className="hidden"
          onChange={handleFileInput}
        />
      </div>

      <div className="flex-1 min-h-0 flex flex-col gap-2">
        <label className="text-xs text-zinc-400">或粘贴 PEM 文本</label>
        <textarea
          ref={textareaRef}
          value={pemText}
          onChange={handleTextChange}
          onPaste={handlePaste}
          placeholder="-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgISA..."
          className="flex-1 min-h-[120px] w-full bg-zinc-900/50 border border-zinc-700 rounded-md p-3 text-xs font-mono text-zinc-300 placeholder-zinc-600 resize-none focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all"
          spellCheck={false}
        />
        <button
          onClick={handleParsePEM}
          disabled={!pemText.trim()}
          className={cn(
            'w-full py-2 rounded-md text-sm font-medium transition-all flex items-center justify-center gap-2',
            pemText.trim()
              ? 'bg-emerald-500 text-zinc-900 hover:bg-emerald-400'
              : 'bg-zinc-800 text-zinc-500 cursor-not-allowed'
          )}
        >
          <Plus className="w-4 h-4" />
          解析并添加为
          {selectedRole === 'leaf' ? '叶子证书' : selectedRole === 'intermediate' ? '中间证书' : '根证书'}
        </button>
      </div>

      {error && (
        <div className="p-3 bg-red-500/10 border border-red-500/30 rounded-md">
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      <div className="flex flex-col gap-2 mt-2">
        <h3 className="text-xs font-medium text-zinc-400">已加载证书</h3>

        {leafCert && (
          <CertBadge
            role="leaf"
            name={getCertDisplayName(leafCert)}
            onRemove={() => clearAll()}
          />
        )}

        {intermediateCerts.map((cert, i) => (
          <CertBadge
            key={i}
            role="intermediate"
            name={getCertDisplayName(cert)}
            onRemove={() => removeIntermediateCert(i)}
          />
        ))}

        {rootCerts.map((cert, i) => (
          <CertBadge
            key={i}
            role="root"
            name={getCertDisplayName(cert)}
            onRemove={() => removeRootCert(i)}
          />
        ))}

        {!leafCert && intermediateCerts.length === 0 && rootCerts.length === 0 && (
          <p className="text-xs text-zinc-600 text-center py-4">暂无证书</p>
        )}
      </div>
    </div>
  );
}

function CertBadge({
  role,
  name,
  onRemove,
}: {
  role: CertRole;
  name: string;
  onRemove: () => void;
}) {
  const colorClasses = {
    leaf: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    intermediate: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    root: 'bg-sky-500/10 border-sky-500/30 text-sky-400',
  };

  const iconComponents = {
    leaf: Leaf,
    intermediate: GitBranch,
    root: TreeDeciduous,
  };

  const Icon = iconComponents[role];
  const labels = { leaf: '叶子', intermediate: '中间', root: '根' };

  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 rounded-md border text-xs',
        colorClasses[role]
      )}
    >
      <Icon className="w-3.5 h-3.5 flex-shrink-0" />
      <span className="text-xs text-zinc-500">{labels[role]}</span>
      <span className="flex-1 truncate font-mono text-xs">{name}</span>
      <button
        onClick={onRemove}
        className="text-zinc-500 hover:text-zinc-300 transition-colors"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  );
}

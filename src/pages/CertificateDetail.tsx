import { useState, useMemo, useEffect } from 'react';
import {
  ShieldAlert,
  Calendar,
  User,
  Building2,
  Key,
  FileText,
  Hash,
  Globe,
  AlertTriangle,
  Search,
  Clock,
  RotateCcw,
} from 'lucide-react';
import ErrorBoundary from '@/components/ErrorBoundary';
import { tryParseCertificate, evaluateValidity } from '@/utils/cert-detail';
import { oidToLongName } from '@/utils/oids';
import type { Extension } from '@/utils/x509';

const STORAGE_KEY_PEM = 'certscope:detail:pem';
const STORAGE_KEY_EVAL = 'certscope:detail:evalAt';

function pad2(n: number): string {
  return n.toString().padStart(2, '0');
}

function toDateTimeLocalValue(date: Date): string {
  return `${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())}T${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())}`;
}

function parseDateTimeLocalValue(value: string): Date | null {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})$/.exec(value);
  if (!match) return null;
  const [, y, mo, d, h, mi] = match;
  return new Date(Date.UTC(Number(y), Number(mo) - 1, Number(d), Number(h), Number(mi), 0));
}

function formatDateTimeUTC(date: Date): string {
  return `${date.getUTCFullYear()}-${pad2(date.getUTCMonth() + 1)}-${pad2(date.getUTCDate())} ${pad2(date.getUTCHours())}:${pad2(date.getUTCMinutes())} UTC`;
}

function formatDate(date: Date): string {
  return date.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
}

function formatSerial(serial: string): string {
  const match = serial.match(/0x([0-9a-fA-F]+)/);
  if (match) {
    return match[1].toUpperCase();
  }
  return serial;
}

const STATE_STYLES: Record<string, string> = {
  'not-yet-valid': 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  valid: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
  expired: 'bg-red-500/15 text-red-400 border-red-500/30',
};

function Section({
  icon: Icon,
  title,
  children,
}: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="mb-4">
      <h3 className="text-sm font-semibold text-zinc-200 mb-2 flex items-center gap-2">
        <Icon className="w-4 h-4 text-cyan-400" />
        {title}
      </h3>
      <div className="bg-zinc-900/50 rounded-lg border border-zinc-800 p-3 space-y-2">
        {children}
      </div>
    </div>
  );
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3 text-xs">
      <span className="text-zinc-500 w-24 flex-shrink-0">{label}</span>
      <span className={mono ? 'font-mono text-zinc-300 break-all' : 'text-zinc-300 break-all'}>
        {value}
      </span>
    </div>
  );
}

function DNFields({ dn }: { dn: Record<string, string[]> }) {
  const entries = Object.entries(dn);
  if (entries.length === 0) {
    return <p className="text-xs text-zinc-500">（空）</p>;
  }
  return (
    <div className="space-y-1">
      {entries.map(([oid, values]) => (
        <div key={oid} className="flex gap-3 text-xs">
          <span className="text-cyan-500 w-20 flex-shrink-0 font-mono">{oidToLongName(oid)}</span>
          <span className="text-zinc-300 break-all">{values.join(', ')}</span>
        </div>
      ))}
    </div>
  );
}

function ExtensionItem({ ext }: { ext: Extension }) {
  const renderValue = () => {
    switch (ext.oid) {
      case '2.5.29.19': {
        const bc = ext.parsed as { ca?: boolean; pathLen?: number } | undefined;
        return (
          <div className="text-xs text-zinc-300">
            <span className={bc?.ca ? 'text-emerald-400' : 'text-zinc-400'}>
              CA: {bc?.ca ? 'TRUE' : 'FALSE'}
            </span>
            {bc?.pathLen !== undefined && (
              <span className="ml-3">Path Length: {bc.pathLen}</span>
            )}
          </div>
        );
      }
      case '2.5.29.15': {
        const usages = (ext.parsed as { usages?: string[] })?.usages || [];
        return (
          <div className="flex flex-wrap gap-1.5">
            {usages.map((u) => (
              <span key={u} className="text-[11px] px-2 py-0.5 bg-zinc-800 rounded text-zinc-300">
                {u}
              </span>
            ))}
          </div>
        );
      }
      case '2.5.29.37': {
        const usages = (ext.parsed as { usages?: string[] })?.usages || [];
        return (
          <div className="space-y-1">
            {usages.map((u) => (
              <div key={u} className="text-xs text-zinc-300 font-mono">{u}</div>
            ))}
          </div>
        );
      }
      case '2.5.29.17': {
        const san = (ext.parsed as { entries?: { type: string; value: string }[] })?.entries || [];
        return (
          <div className="space-y-1">
            {san.map((entry, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-sky-400 w-16">{entry.type}:</span>
                <span className="text-zinc-300 font-mono break-all">{entry.value}</span>
              </div>
            ))}
          </div>
        );
      }
      case '2.5.29.35':
      case '2.5.29.14': {
        const ki = (ext.parsed as { keyIdentifier?: string })?.keyIdentifier || ext.value;
        return (
          <div className="text-[11px] font-mono text-zinc-300 break-all">
            {typeof ki === 'string' ? ki.match(/.{1,2}/g)?.join(':') : ki}
          </div>
        );
      }
      default:
        return (
          <div className="text-[11px] font-mono text-zinc-400 break-all">{ext.value}</div>
        );
    }
  };

  return (
    <div className="py-2 border-b border-zinc-800/50 last:border-b-0">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-xs font-medium text-zinc-200">{ext.name}</span>
        {ext.critical && (
          <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/20 text-amber-400 rounded">
            critical
          </span>
        )}
        <span className="text-[10px] text-zinc-600 font-mono ml-auto">{ext.oid}</span>
      </div>
      <div className="ml-2">{renderValue()}</div>
    </div>
  );
}

function EvaluationPanel({
  notBefore,
  notAfter,
  evalAtInput,
  onEvalAtChange,
  onResetToNow,
}: {
  notBefore: Date;
  notAfter: Date;
  evalAtInput: string;
  onEvalAtChange: (value: string) => void;
  onResetToNow: () => void;
}) {
  const evalAt = parseDateTimeLocalValue(evalAtInput);

  const evaluation = useMemo(() => {
    if (!evalAt) return null;
    return evaluateValidity(notBefore, notAfter, evalAt);
  }, [notBefore, notAfter, evalAt]);

  return (
    <Section icon={Clock} title="有效期检查">
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-xs text-zinc-500">评估时间 (UTC)</label>
        <input
          type="datetime-local"
          value={evalAtInput}
          onChange={(e) => onEvalAtChange(e.target.value)}
          step="60"
          className="bg-zinc-900 border border-zinc-700 rounded-md px-2 py-1 text-xs text-zinc-200 font-mono focus:outline-none focus:border-cyan-500/50 [color-scheme:dark]"
        />
        <button
          onClick={onResetToNow}
          className="inline-flex items-center gap-1 px-2 py-1 text-xs bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-md transition-colors"
          title="使用当前 UTC 时间"
        >
          <RotateCcw className="w-3 h-3" />
          当前时间
        </button>
      </div>

      {evaluation && (
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <span
            className={`inline-flex items-center gap-2 px-3 py-1.5 rounded-full border text-xs font-medium ${STATE_STYLES[evaluation.state]}`}
          >
            {evaluation.label}
          </span>
          <span className="text-xs text-zinc-400">{evaluation.description}</span>
          <span className="text-[11px] text-zinc-600 font-mono ml-auto">
            评估于 {evalAt ? formatDateTimeUTC(evalAt) : '—'}
          </span>
        </div>
      )}

      {!evaluation && (
        <p className="text-xs text-amber-400/80 mt-2">评估时间格式无效，请重新选择。</p>
      )}
    </Section>
  );
}

function CertificateDetailContent({ pem, evalAtInput, onEvalAtChange, onResetToNow }: {
  pem: string;
  evalAtInput: string;
  onEvalAtChange: (value: string) => void;
  onResetToNow: () => void;
}) {
  const result = useMemo(() => tryParseCertificate(pem), [pem]);

  if (result.ok === false) {
    return (
      <div className="flex flex-col items-center justify-center h-full p-8">
        <div className="w-full max-w-lg bg-red-500/10 border border-red-500/30 rounded-lg p-5">
          <div className="flex items-center gap-2 mb-2">
            <ShieldAlert className="w-5 h-5 text-red-400" />
            <h2 className="text-sm font-semibold text-red-400">无法解析证书</h2>
          </div>
          <p className="text-xs text-red-300/80">{result.error}</p>
        </div>
      </div>
    );
  }

  const fields = result.fields;

  return (
    <div className="h-full overflow-auto pr-2">
      <EvaluationPanel
        notBefore={fields.validity.notBefore}
        notAfter={fields.validity.notAfter}
        evalAtInput={evalAtInput}
        onEvalAtChange={onEvalAtChange}
        onResetToNow={onResetToNow}
      />

      <Section icon={FileText} title="基本信息">
        <Field label="版本" value={`v${fields.version}`} />
        <Field label="序列号" value={formatSerial(fields.serialNumber)} mono />
        <Field
          label="签名算法"
          value={`${fields.signatureAlgorithm.name} (${fields.signatureAlgorithm.oid})`}
          mono
        />
      </Section>

      <Section icon={Building2} title="颁发者 (Issuer)">
        <DNFields dn={fields.issuer} />
      </Section>

      <Section icon={Calendar} title="有效期 (Validity)">
        <Field label="生效时间" value={formatDate(fields.validity.notBefore)} mono />
        <Field label="过期时间" value={formatDate(fields.validity.notAfter)} mono />
      </Section>

      <Section icon={User} title="主题 (Subject)">
        <DNFields dn={fields.subject} />
      </Section>

      <Section icon={Key} title="公钥信息 (Subject Public Key Info)">
        <Field
          label="算法"
          value={`${fields.subjectPublicKeyInfo.algorithm.name} (${fields.subjectPublicKeyInfo.algorithm.oid})`}
          mono
        />
        {fields.subjectPublicKeyInfo.keySize && (
          <Field label="密钥长度" value={`${fields.subjectPublicKeyInfo.keySize} bit`} />
        )}
        {fields.subjectPublicKeyInfo.curve && (
          <Field label="曲线" value={fields.subjectPublicKeyInfo.curve} />
        )}
      </Section>

      {fields.san && fields.san.length > 0 && (
        <Section icon={Globe} title="主题备用名称 (SAN)">
          <div className="space-y-1">
            {fields.san.map((entry, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-sky-400 w-16">{entry.type}:</span>
                <span className="text-zinc-300 font-mono break-all">{entry.value}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      <Section icon={Hash} title="扩展字段 (Extensions)">
        {fields.extensions.length === 0 ? (
          <p className="text-xs text-zinc-500">无扩展</p>
        ) : (
          <div>
            {fields.extensions.map((ext, i) => (
              <ExtensionItem key={i} ext={ext} />
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

const SAMPLE = `-----BEGIN CERTIFICATE-----
（在此粘贴 PEM 证书文本）
-----END CERTIFICATE-----`;

export default function CertificateDetail() {
  const [pem, setPem] = useState<string>(() => {
    if (typeof window === 'undefined') return '';
    try {
      return window.localStorage.getItem(STORAGE_KEY_PEM) || '';
    } catch {
      return '';
    }
  });

  const [evalAtInput, setEvalAtInput] = useState<string>(() => {
    if (typeof window === 'undefined') return toDateTimeLocalValue(new Date());
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY_EVAL);
      if (stored && parseDateTimeLocalValue(stored)) return stored;
    } catch {
    }
    return toDateTimeLocalValue(new Date());
  });

  useEffect(() => {
    try {
      window.localStorage.setItem(STORAGE_KEY_PEM, pem);
    } catch {
    }
  }, [pem]);

  useEffect(() => {
    if (parseDateTimeLocalValue(evalAtInput)) {
      try {
        window.localStorage.setItem(STORAGE_KEY_EVAL, evalAtInput);
      } catch {
      }
    }
  }, [evalAtInput]);

  const handleResetToNow = () => {
    setEvalAtInput(toDateTimeLocalValue(new Date()));
  };

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100">
      <header className="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-5xl mx-auto px-4 py-3 flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
            <FileText className="w-5 h-5 text-cyan-400" />
          </div>
          <div>
            <h1 className="text-base font-bold text-zinc-100">证书详情</h1>
            <p className="text-[11px] text-zinc-500">粘贴 PEM 证书以查看解析后的字段</p>
          </div>
        </div>
      </header>

      <main className="max-w-5xl mx-auto px-4 py-4">
        <div className="mb-4">
          <label className="block text-xs text-zinc-400 mb-2 flex items-center gap-2">
            <Search className="w-3.5 h-3.5" />
            PEM 证书文本
          </label>
          <textarea
            value={pem}
            onChange={(e) => setPem(e.target.value)}
            placeholder={SAMPLE}
            spellCheck={false}
            className="w-full h-40 bg-zinc-900/50 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-300 placeholder-zinc-600 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all resize-y"
          />
          {pem.trim() && (
            <button
              onClick={() => setPem('')}
              className="mt-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              清空
            </button>
          )}
        </div>

        {!pem.trim() ? (
          <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
            <AlertTriangle className="w-10 h-10 mb-3 opacity-30" />
            <p className="text-sm">请在上方粘贴 PEM 证书以查看详情</p>
          </div>
        ) : (
          <ErrorBoundary>
            <CertificateDetailContent
              pem={pem}
              evalAtInput={evalAtInput}
              onEvalAtChange={setEvalAtInput}
              onResetToNow={handleResetToNow}
            />
          </ErrorBoundary>
        )}
      </main>
    </div>
  );
}

import { useState, useMemo, useEffect } from 'react';
import {
  Shield,
  FileText,
  Building2,
  User,
  Calendar,
  Key,
  Hash,
  Globe,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Search,
  RefreshCw,
} from 'lucide-react';
import ErrorBoundary from '@/components/ErrorBoundary';
import { oidToLongName } from '@/utils/oids';
import {
  parseCertificateInput,
  getValidityInfo,
  parseEvalTime,
  formatEvalInputValue,
  CertificateDetail,
  ValidityStatus,
} from '@/utils/certificate-detail';

const STORAGE_KEY_PEM = 'certscope.detail.pem';
const STORAGE_KEY_EVAL_TIME = 'certscope.detail.evalTime';

function loadStored(key: string): string | null {
  try {
    return localStorage.getItem(key);
  } catch {
    return null;
  }
}

function saveStored(key: string, value: string) {
  try {
    localStorage.setItem(key, value);
  } catch {
    return;
  }
}

function formatDate(date: Date): string {
  return date.toLocaleString('zh-CN', {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    timeZone: 'UTC',
    timeZoneName: 'short',
  });
}

function formatSerial(serial: string): string {
  const match = serial.match(/0x([0-9a-fA-F]+)/);
  if (match) return match[1].toUpperCase();
  return serial;
}

function StatusBadge({ status }: { status: ValidityStatus }) {
  const config = {
    valid: {
      label: '有效',
      classes: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
      icon: CheckCircle2,
    },
    expired: {
      label: '已过期',
      classes: 'bg-red-500/10 border-red-500/30 text-red-400',
      icon: XCircle,
    },
    notYetValid: {
      label: '尚未生效',
      classes: 'bg-amber-500/10 border-amber-500/30 text-amber-400',
      icon: Clock,
    },
  }[status];
  const Icon = config.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 text-xs rounded-md border ${config.classes}`}>
      <Icon className="w-3.5 h-3.5" />
      {config.label}
    </span>
  );
}

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
        <Icon className="w-4 h-4 text-emerald-400" />
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
  return (
    <div className="space-y-1">
      {Object.entries(dn).map(([oid, values]) => (
        <div key={oid} className="flex gap-3 text-xs">
          <span className="text-emerald-500 w-20 flex-shrink-0 font-mono">
            {oidToLongName(oid)}
          </span>
          <span className="text-zinc-300 break-all">{values.join(', ')}</span>
        </div>
      ))}
    </div>
  );
}

function describeValidity(status: ValidityStatus, days: number): string {
  if (status === 'notYetValid') {
    return `尚未生效，${days > 0 ? `距离生效还有 ${days} 天` : '即将在 24 小时内生效'}`;
  }
  if (status === 'expired') {
    return `已经过期${days > 0 ? ` ${days} 天` : '（24 小时内刚过期）'}`;
  }
  return days > 0 ? `当前有效，还有 ${days} 天过期` : '当前有效，将在 24 小时内过期';
}

function DetailContent({ detail, now }: { detail: CertificateDetail; now: Date }) {
  const validity = getValidityInfo(detail.notBefore, detail.notAfter, now);
  return (
    <div className="h-full overflow-auto pr-2" data-testid="cert-detail">
      <div
        data-testid="validity-summary"
        data-status={validity.status}
        className={`mb-4 p-3 rounded-lg border flex items-center gap-3 ${
          validity.status === 'valid'
            ? 'bg-emerald-500/10 border-emerald-500/30'
            : validity.status === 'expired'
            ? 'bg-red-500/10 border-red-500/30'
            : 'bg-amber-500/10 border-amber-500/30'
        }`}
      >
        <StatusBadge status={validity.status} />
        <span
          className={`text-sm ${
            validity.status === 'valid'
              ? 'text-emerald-400'
              : validity.status === 'expired'
              ? 'text-red-400'
              : 'text-amber-400'
          }`}
        >
          {describeValidity(validity.status, validity.days)}
        </span>
        <span className="text-xs text-zinc-500 ml-auto whitespace-nowrap">
          评估时间：{formatDate(now)}
        </span>
      </div>

      <Section icon={FileText} title="基本信息">
        <Field label="版本" value={`v${detail.version}`} />
        <Field label="序列号" value={formatSerial(detail.serialNumber)} mono />
        <Field
          label="签名算法"
          value={`${detail.signatureAlgorithm.name} (${detail.signatureAlgorithm.oid})`}
          mono
        />
      </Section>

      <Section icon={Building2} title="颁发者 (Issuer)">
        <DNFields dn={detail.issuer} />
      </Section>

      <Section icon={Calendar} title="有效期 (Validity)">
        <Field label="生效时间" value={formatDate(detail.notBefore)} />
        <Field label="过期时间" value={formatDate(detail.notAfter)} />
        <Field
          label="状态"
          value={describeValidity(validity.status, validity.days)}
        />
      </Section>

      <Section icon={User} title="主题 (Subject)">
        <DNFields dn={detail.subject} />
      </Section>

      <Section icon={Key} title="公钥算法 (Subject Public Key Info)">
        <Field
          label="算法"
          value={`${detail.publicKeyAlgorithm.name} (${detail.publicKeyAlgorithm.oid})`}
          mono
        />
        {detail.publicKeyAlgorithm.keySize !== undefined && (
          <Field label="密钥长度" value={`${detail.publicKeyAlgorithm.keySize} bit`} />
        )}
        {detail.publicKeyAlgorithm.curve && (
          <Field label="曲线" value={detail.publicKeyAlgorithm.curve} />
        )}
      </Section>

      {detail.basicConstraints && (
        <Section icon={Shield} title="基本约束 (Basic Constraints)">
          <Field label="CA" value={detail.basicConstraints.ca ? 'TRUE' : 'FALSE'} />
          {detail.basicConstraints.pathLen !== undefined && (
            <Field label="路径长度" value={String(detail.basicConstraints.pathLen)} />
          )}
        </Section>
      )}

      {detail.keyUsage && detail.keyUsage.length > 0 && (
        <Section icon={Hash} title="密钥用法 (Key Usage)">
          <div className="flex flex-wrap gap-2">
            {detail.keyUsage.map((u) => (
              <span key={u} className="text-xs px-2 py-0.5 bg-zinc-800 rounded text-zinc-300">
                {u}
              </span>
            ))}
          </div>
        </Section>
      )}

      {detail.extKeyUsage && detail.extKeyUsage.length > 0 && (
        <Section icon={Hash} title="扩展密钥用法 (Extended Key Usage)">
          <div className="space-y-1">
            {detail.extKeyUsage.map((u) => (
              <div key={u} className="text-xs font-mono text-zinc-300 break-all">
                {u}
              </div>
            ))}
          </div>
        </Section>
      )}

      {detail.san && detail.san.length > 0 && (
        <Section icon={Globe} title="主题备用名称 (Subject Alternative Name)">
          <div className="space-y-1">
            {detail.san.map((entry, i) => (
              <div key={i} className="flex gap-2 text-xs">
                <span className="text-sky-400 w-16 flex-shrink-0">{entry.type}:</span>
                <span className="text-zinc-300 font-mono break-all">{entry.value}</span>
              </div>
            ))}
          </div>
        </Section>
      )}

      {(detail.ski || detail.aki) && (
        <Section icon={Key} title="密钥标识符">
          {detail.ski && <Field label="SKI" value={detail.ski} mono />}
          {detail.aki && <Field label="AKI" value={detail.aki} mono />}
        </Section>
      )}

      {detail.extensions.length > 0 && (
        <Section icon={Hash} title={`全部扩展 (${detail.extensions.length})`}>
          <div className="space-y-2">
            {detail.extensions.map((ext, i) => (
              <div key={i} className="text-xs flex items-center gap-2 py-1 border-b border-zinc-800/50 last:border-b-0">
                <span className="text-zinc-200">{ext.name}</span>
                {ext.critical && (
                  <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/20 text-amber-400 rounded">
                    critical
                  </span>
                )}
                <span className="text-[10px] text-zinc-600 font-mono ml-auto break-all">
                  {ext.oid}
                </span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  );
}

export default function CertificateDetailPage({ now }: { now?: Date }) {
  const [pem, setPem] = useState(() => loadStored(STORAGE_KEY_PEM) ?? '');
  const [submitted, setSubmitted] = useState(() => loadStored(STORAGE_KEY_PEM) ?? '');
  const [evalTime, setEvalTime] = useState(() => {
    const stored = loadStored(STORAGE_KEY_EVAL_TIME);
    if (stored) return stored;
    return formatEvalInputValue(now ?? new Date());
  });

  useEffect(() => {
    saveStored(STORAGE_KEY_PEM, submitted);
  }, [submitted]);

  useEffect(() => {
    saveStored(STORAGE_KEY_EVAL_TIME, evalTime);
  }, [evalTime]);

  const referenceNow = useMemo(() => {
    try {
      return parseEvalTime(evalTime);
    } catch {
      return now ?? new Date();
    }
  }, [evalTime, now]);

  const result = useMemo(
    () => (submitted ? parseCertificateInput(submitted) : null),
    [submitted],
  );

  const handleParse = () => {
    setSubmitted(pem);
  };

  const handleUseCurrentTime = () => {
    setEvalTime(formatEvalInputValue(new Date()));
  };

  return (
    <ErrorBoundary>
      <div className="min-h-screen bg-zinc-950 text-zinc-100">
        <header className="border-b border-zinc-800 bg-zinc-900/50">
          <div className="max-w-5xl mx-auto px-4 py-4">
            <h1 className="text-lg font-bold flex items-center gap-2">
              <Shield className="w-5 h-5 text-emerald-400" />
              证书详情
            </h1>
            <p className="text-xs text-zinc-500 mt-1">
              粘贴 PEM 证书查看序列号、主题、颁发者、有效期、公钥与签名算法及常用扩展
            </p>
          </div>
        </header>

        <main className="max-w-5xl mx-auto px-4 py-6">
          <div className="mb-4">
            <textarea
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              spellCheck={false}
              placeholder={'-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'}
              className="w-full h-40 bg-zinc-900/50 border border-zinc-700 rounded-lg p-3 text-xs font-mono text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/20 transition-all resize-y"
            />
            <div className="mt-3 flex flex-wrap items-center gap-3">
              <button
                onClick={handleParse}
                disabled={!pem.trim()}
                className="inline-flex items-center gap-2 px-4 py-2 bg-emerald-500 text-zinc-900 rounded-lg text-sm font-medium hover:bg-emerald-400 transition-colors disabled:bg-zinc-800 disabled:text-zinc-500 disabled:cursor-not-allowed"
              >
                <Search className="w-4 h-4" />
                解析证书
              </button>
              <div className="flex items-center gap-2">
                <label htmlFor="eval-time" className="text-xs text-zinc-400 whitespace-nowrap">
                  评估时间 (UTC)
                </label>
                <input
                  id="eval-time"
                  data-testid="eval-time"
                  type="datetime-local"
                  value={evalTime}
                  onChange={(e) => setEvalTime(e.target.value)}
                  step={60}
                  className="bg-zinc-900/50 border border-zinc-700 rounded-md px-2 py-1.5 text-xs text-zinc-200 focus:outline-none focus:border-emerald-500/50 [color-scheme:dark]"
                />
                <button
                  onClick={handleUseCurrentTime}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-300 rounded-md text-xs transition-colors"
                  title="使用当前 UTC 时间"
                >
                  <RefreshCw className="w-3 h-3" />
                  当前时间
                </button>
              </div>
            </div>
          </div>

          {result?.ok === true && <DetailContent detail={result.detail} now={referenceNow} />}

          {result?.ok === false && (
            <div
              data-testid="parse-error"
              className="p-4 bg-red-500/10 border border-red-500/30 rounded-lg flex items-start gap-3"
            >
              <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-red-400">无法解析证书</p>
                <p className="text-xs text-red-400/80 mt-1 break-all">{result.error}</p>
              </div>
            </div>
          )}

          {!result && (
            <div className="flex flex-col items-center justify-center py-20 text-zinc-500">
              <FileText className="w-12 h-12 mb-4 opacity-30" />
              <p className="text-sm">粘贴证书并点击“解析证书”以查看详情</p>
            </div>
          )}
        </main>
      </div>
    </ErrorBoundary>
  );
}

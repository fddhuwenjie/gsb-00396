import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  AlertTriangle,
  ArrowLeft,
  Calendar,
  CheckCircle2,
  Clock,
  FileKey,
  FileText,
  Hash,
  Key,
  Shield,
  XCircle,
} from 'lucide-react';
import { useCertificateStore } from '@/store/certificateStore';
import { evaluateValidity, ValidityStatus } from '@/utils/x509';
import { oidToLongName } from '@/utils/oids';
import ErrorBoundary from '@/components/ErrorBoundary';
import { ExtensionItem } from '@/components/X509Fields';

const STORAGE_KEY = 'certscope:lastValidityEvaluation';

interface SavedEvaluation {
  verifyAt: string;
  status: ValidityStatus;
  days: number;
  subject: string;
  serialNumber: string;
}

function loadSavedEvaluation(): SavedEvaluation | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (typeof parsed?.verifyAt !== 'string' || typeof parsed?.days !== 'number') return null;
    if (!['not-yet-valid', 'valid', 'expired'].includes(parsed?.status)) return null;
    return parsed as SavedEvaluation;
  } catch {
    return null;
  }
}

const STATUS_TEXT: Record<ValidityStatus, string> = {
  'not-yet-valid': '尚未生效',
  valid: '当前有效',
  expired: '已经过期',
};

function daysText(status: ValidityStatus, days: number): string {
  switch (status) {
    case 'not-yet-valid':
      return `距离生效还有 ${days} 天`;
    case 'valid':
      return `距离过期还有 ${days} 天`;
    case 'expired':
      return `已过期 ${days} 天`;
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
  return match ? match[1].toUpperCase() : serial;
}

function toDatetimeLocal(date: Date): string {
  const pad = (n: number) => String(n).padStart(2, '0');
  return (
    `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}` +
    `T${pad(date.getHours())}:${pad(date.getMinutes())}`
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex gap-3 py-1.5 text-sm border-b border-zinc-800/50 last:border-b-0">
      <span className="text-zinc-500 w-28 flex-shrink-0">{label}</span>
      <span className={mono ? 'font-mono text-zinc-200 break-all' : 'text-zinc-200 break-all'}>
        {value}
      </span>
    </div>
  );
}

function Card({ icon: Icon, title, children }: {
  icon: React.ComponentType<{ className?: string }>;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="bg-zinc-900/50 rounded-xl border border-zinc-800 p-4 mb-4">
      <h2 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
        <Icon className="w-4 h-4 text-emerald-400" />
        {title}
      </h2>
      {children}
    </section>
  );
}

function DNRows({ dn }: { dn: Record<string, string[]> }) {
  const entries = Object.entries(dn);
  if (entries.length === 0) {
    return <p className="text-xs text-zinc-500">（空）</p>;
  }
  return (
    <>
      {entries.map(([oid, values]) => (
        <Row key={oid} label={oidToLongName(oid)} value={values.join(', ')} />
      ))}
    </>
  );
}

function CertificateDetailContent() {
  const { leafCert, error, setLeafCertFromPEM } = useCertificateStore();
  const [pemText, setPemText] = useState('');
  const [saved] = useState<SavedEvaluation | null>(() => loadSavedEvaluation());
  const [verifyAt, setVerifyAt] = useState(
    () => loadSavedEvaluation()?.verifyAt || toDatetimeLocal(new Date()),
  );

  const fields = leafCert?.fields;
  const at = new Date(verifyAt);
  const evaluation =
    fields && !Number.isNaN(at.getTime()) ? evaluateValidity(fields.validity, at) : null;

  // 相同证书 + 相同评估时间 => 相同结果；持久化最后一次评估时间与结果
  useEffect(() => {
    if (!evaluation || !fields) return;
    const record: SavedEvaluation = {
      verifyAt,
      status: evaluation.status,
      days: evaluation.days,
      subject: fields.subjectRaw,
      serialNumber: fields.serialNumber,
    };
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(record));
    } catch {
      // 存储不可用时忽略，不影响评估功能
    }
  }, [evaluation, fields, verifyAt]);

  if (!leafCert) {
    return (
      <div className="max-w-2xl mx-auto">
        {saved && (
          <Card icon={Clock} title="上次评估结果">
            <Row label="证书主题" value={saved.subject} />
            <Row label="评估时间" value={saved.verifyAt.replace('T', ' ')} />
            <div className="flex items-center gap-2 pt-2">
              <StatusBadge status={saved.status} />
              <span className="text-xs text-zinc-400">{daysText(saved.status, saved.days)}</span>
            </div>
          </Card>
        )}
        <Card icon={FileKey} title="加载证书">
          <textarea
            value={pemText}
            onChange={(e) => setPemText(e.target.value)}
            placeholder="粘贴 PEM 格式证书（-----BEGIN CERTIFICATE-----）"
            className="w-full h-40 bg-zinc-950 border border-zinc-800 rounded-lg p-3 text-xs font-mono text-zinc-300 focus:outline-none focus:border-emerald-500/50 resize-y"
          />
          {error && (
            <div className="mt-3 p-3 rounded-lg border bg-red-500/10 border-red-500/30 flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-xs font-medium text-red-400">证书解析失败</p>
                <p className="text-xs text-red-400/80 mt-0.5">{error}</p>
              </div>
            </div>
          )}
          <button
            onClick={() => setLeafCertFromPEM(pemText)}
            disabled={!pemText.trim()}
            className="mt-3 w-full py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm transition-colors disabled:opacity-40 disabled:hover:bg-emerald-600"
          >
            解析证书
          </button>
        </Card>
      </div>
    );
  }

  return (
    <div className="max-w-3xl mx-auto">
      {error && (
        <div className="mb-4 p-3 rounded-lg border bg-red-500/10 border-red-500/30 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
          <p className="text-xs text-red-400">{error}</p>
        </div>
      )}

      <Card icon={FileText} title="基本信息">
        <Row label="序列号" value={formatSerial(fields!.serialNumber)} mono />
        <Row
          label="签名算法"
          value={`${fields!.signatureAlgorithm.name} (${fields!.signatureAlgorithm.oid})`}
          mono
        />
        <Row
          label="公钥算法"
          value={
            `${fields!.subjectPublicKeyInfo.algorithm.name} (${fields!.subjectPublicKeyInfo.algorithm.oid})` +
            (fields!.subjectPublicKeyInfo.keySize ? ` · ${fields!.subjectPublicKeyInfo.keySize} bit` : '') +
            (fields!.subjectPublicKeyInfo.curve ? ` · ${fields!.subjectPublicKeyInfo.curve}` : '')
          }
          mono
        />
      </Card>

      <Card icon={Shield} title="主题">
        <DNRows dn={fields!.subject} />
      </Card>

      <Card icon={Shield} title="颁发者">
        <DNRows dn={fields!.issuer} />
      </Card>

      <Card icon={Calendar} title="有效期">
        <Row label="生效时间" value={formatDate(fields!.validity.notBefore)} />
        <Row label="过期时间" value={formatDate(fields!.validity.notAfter)} />
        <div className="flex flex-wrap items-center gap-3 pt-3">
          <label className="text-xs text-zinc-500 flex-shrink-0">评估时间</label>
          <input
            type="datetime-local"
            value={verifyAt}
            onChange={(e) => setVerifyAt(e.target.value)}
            className="bg-zinc-950 border border-zinc-800 rounded-lg px-2 py-1 text-xs text-zinc-300 focus:outline-none focus:border-emerald-500/50"
          />
          {evaluation && (
            <>
              <StatusBadge status={evaluation.status} />
              <span className="text-xs text-zinc-400">
                {daysText(evaluation.status, evaluation.days)}
              </span>
            </>
          )}
        </div>
      </Card>

      <Card icon={Hash} title={`扩展字段（${fields!.extensions.length}）`}>
        {fields!.extensions.length === 0 ? (
          <p className="text-xs text-zinc-500">无扩展</p>
        ) : (
          fields!.extensions.map((ext, i) => <ExtensionItem key={i} ext={ext} />)
        )}
      </Card>
    </div>
  );
}

function StatusBadge({ status }: { status: ValidityStatus }) {
  const styles: Record<ValidityStatus, string> = {
    'not-yet-valid': 'bg-amber-500/10 border-amber-500/30 text-amber-400',
    valid: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400',
    expired: 'bg-red-500/10 border-red-500/30 text-red-400',
  };
  const icons: Record<ValidityStatus, React.ReactNode> = {
    'not-yet-valid': <Clock className="w-3.5 h-3.5" />,
    valid: <CheckCircle2 className="w-3.5 h-3.5" />,
    expired: <XCircle className="w-3.5 h-3.5" />,
  };
  return (
    <span
      className={`flex items-center gap-1 px-2 py-0.5 rounded border text-xs font-medium ${styles[status]}`}
    >
      {icons[status]}
      {STATUS_TEXT[status]}
    </span>
  );
}

export default function CertificateDetail() {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col">
      <header className="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center gap-3">
          <Link
            to="/"
            className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors"
            title="返回首页"
          >
            <ArrowLeft className="w-4 h-4" />
          </Link>
          <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
            <FileKey className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-base font-bold text-zinc-100">证书详情</h1>
            <p className="text-[11px] text-zinc-500">CertScope</p>
          </div>
        </div>
      </header>

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-6">
        <ErrorBoundary>
          <CertificateDetailContent />
        </ErrorBoundary>
      </main>
    </div>
  );
}

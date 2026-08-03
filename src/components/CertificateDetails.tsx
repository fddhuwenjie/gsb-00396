import { useEffect, useMemo, useState } from 'react';
import {
  ScrollText,
  Hash,
  User,
  Building2,
  Calendar,
  Key,
  FileSignature,
  Puzzle,
  AlertTriangle,
  CheckCircle2,
  Clock,
  XCircle,
} from 'lucide-react';
import { useCertificateStore } from '@/store/certificateStore';
import {
  describeCertificateFromPEM,
  checkValidity,
  CertificateSummary,
  ValidityStatus,
  ValidityCheck,
} from '@/utils/certDetails';

const LAST_EVAL_KEY = 'certscope.details.lastEvaluation';

interface PersistedEvaluation {
  /** Raw value from the datetime-local input (empty means "use current time"). */
  verifyTimeInput: string;
  /** Serial number of the certificate the evaluation referred to. */
  serialNumber: string;
  check: ValidityCheck;
  /** ISO timestamp of the verification time actually used. */
  evaluatedAt: string;
}

function loadPersistedEvaluation(): PersistedEvaluation | null {
  try {
    const raw = localStorage.getItem(LAST_EVAL_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as PersistedEvaluation;
  } catch {
    return null;
  }
}

function savePersistedEvaluation(evaluation: PersistedEvaluation): void {
  try {
    localStorage.setItem(LAST_EVAL_KEY, JSON.stringify(evaluation));
  } catch {
    // Ignore quota / unavailable storage — persistence is best-effort.
  }
}

/**
 * Interpret a datetime-local value (e.g. "2027-01-01T00:00") as an absolute UTC
 * instant so the evaluation is deterministic and independent of the host's
 * local time zone. Returns null when the input is empty or unparseable.
 */
function parseVerifyTimeUTC(input: string): Date | null {
  if (!input) return null;
  const withSeconds = /T\d{2}:\d{2}$/.test(input) ? `${input}:00` : input;
  const parsed = new Date(`${withSeconds}Z`);
  return isNaN(parsed.getTime()) ? null : parsed;
}

function formatDate(date: Date): string {
  if (isNaN(date.getTime())) return '(无效日期)';
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
        {value || '—'}
      </span>
    </div>
  );
}

const VALIDITY_LABEL: Record<ValidityStatus, string> = {
  valid: '当前有效',
  'not-yet-valid': '尚未生效',
  expired: '已经过期',
};

const VALIDITY_STYLE: Record<ValidityStatus, string> = {
  valid: 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30',
  'not-yet-valid': 'bg-sky-500/10 text-sky-400 border-sky-500/30',
  expired: 'bg-red-500/10 text-red-400 border-red-500/30',
};

function ValidityIcon({ status }: { status: ValidityStatus }) {
  if (status === 'valid') return <CheckCircle2 className="w-3.5 h-3.5" />;
  if (status === 'not-yet-valid') return <Clock className="w-3.5 h-3.5" />;
  return <XCircle className="w-3.5 h-3.5" />;
}

function validityDetail(check: ValidityCheck): string {
  switch (check.status) {
    case 'not-yet-valid':
      return `距离生效还有 ${check.daysUntilValid} 天`;
    case 'valid':
      return `距离过期还有 ${check.daysUntilExpiry} 天`;
    case 'expired':
      return `已过期 ${check.daysSinceExpiry} 天`;
  }
}

function ValidityResult({ check }: { check: ValidityCheck }) {
  return (
    <div className={`flex items-center gap-2 text-xs px-2 py-1 rounded border ${VALIDITY_STYLE[check.status]}`}>
      <ValidityIcon status={check.status} />
      <span className="font-medium">{VALIDITY_LABEL[check.status]}</span>
      <span className="opacity-80">· {validityDetail(check)}</span>
    </div>
  );
}

function CertificateSummaryView({ summary }: { summary: CertificateSummary }) {
  // Validity is evaluated against a user-controlled verification time so the
  // status never silently depends on "today". The input is interpreted as UTC,
  // making the result deterministic for identical input + evaluation time.
  const persisted = useMemo(() => loadPersistedEvaluation(), []);
  const [verifyTimeInput, setVerifyTimeInput] = useState(
    persisted && persisted.serialNumber === summary.serialNumber ? persisted.verifyTimeInput : '',
  );

  const verificationTime = useMemo(() => {
    return parseVerifyTimeUTC(verifyTimeInput) ?? new Date();
  }, [verifyTimeInput]);

  const check = useMemo(
    () => checkValidity(summary, verificationTime),
    [summary, verificationTime],
  );

  // Persist the last evaluation so it survives a page refresh.
  useEffect(() => {
    savePersistedEvaluation({
      verifyTimeInput,
      serialNumber: summary.serialNumber,
      check,
      evaluatedAt: verificationTime.toISOString(),
    });
  }, [verifyTimeInput, summary.serialNumber, check, verificationTime]);

  const keyLine = [
    summary.publicKeyAlgorithm,
    summary.keySize ? `${summary.keySize} bit` : null,
    summary.curve ? `曲线 ${summary.curve}` : null,
  ]
    .filter(Boolean)
    .join(' · ');

  return (
    <div>
      <Section icon={Hash} title="基本信息">
        <Field label="序列号" value={summary.serialNumber} mono />
        <Field
          label="签名算法"
          value={`${summary.signatureAlgorithm} (${summary.signatureOid})`}
          mono
        />
      </Section>

      <Section icon={User} title="主题 (Subject)">
        <Field label="DN" value={summary.subject} mono />
      </Section>

      <Section icon={Building2} title="颁发者 (Issuer)">
        <Field label="DN" value={summary.issuer} mono />
      </Section>

      <Section icon={Calendar} title="有效期检查">
        <Field label="生效时间" value={formatDate(summary.notBefore)} />
        <Field label="过期时间" value={formatDate(summary.notAfter)} />
        <div className="flex flex-wrap items-center gap-3 pt-1">
          <label className="text-zinc-500 text-xs w-24 flex-shrink-0">评估时间 (UTC)</label>
          <input
            type="datetime-local"
            step={1}
            value={verifyTimeInput}
            onChange={(e) => setVerifyTimeInput(e.target.value)}
            className="bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-200"
          />
          {verifyTimeInput && (
            <button
              onClick={() => setVerifyTimeInput('')}
              className="text-[11px] text-zinc-500 hover:text-zinc-300 underline"
            >
              使用当前时间
            </button>
          )}
        </div>
        <div className="flex items-center gap-3 pt-1">
          <span className="text-zinc-500 text-xs w-24 flex-shrink-0">评估结果</span>
          <ValidityResult check={check} />
        </div>
        <div className="flex items-center gap-3">
          <span className="text-zinc-500 text-xs w-24 flex-shrink-0" />
          <span className="text-[11px] text-zinc-600">
            按 {formatDate(verificationTime)} 评估
          </span>
        </div>
      </Section>

      <Section icon={Key} title="公钥信息">
        <Field label="算法" value={`${keyLine} (${summary.publicKeyOid})`} mono />
      </Section>

      <Section icon={FileSignature} title="签名算法">
        <Field label="算法" value={`${summary.signatureAlgorithm} (${summary.signatureOid})`} mono />
      </Section>

      <Section icon={Puzzle} title="常用扩展">
        {summary.extensions.length === 0 ? (
          <p className="text-xs text-zinc-500">无扩展</p>
        ) : (
          <div className="space-y-1">
            {summary.extensions.map((ext, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <span className="text-zinc-200">{ext.name}</span>
                {ext.critical && (
                  <span className="text-[10px] px-1.5 py-0.5 bg-amber-500/20 text-amber-400 rounded">
                    critical
                  </span>
                )}
                <span className="text-[10px] text-zinc-600 font-mono ml-auto">{ext.oid}</span>
              </div>
            ))}
          </div>
        )}
      </Section>
    </div>
  );
}

const LAST_PEM_KEY = 'certscope.details.lastPem';

export default function CertificateDetails() {
  const leafCert = useCertificateStore((s) => s.leafCert);
  const [pem, setPem] = useState(() => {
    try {
      return localStorage.getItem(LAST_PEM_KEY) ?? '';
    } catch {
      return '';
    }
  });

  // Persist the pasted PEM so the last evaluated certificate is restored on
  // refresh (alongside the persisted evaluation time and result).
  useEffect(() => {
    try {
      if (pem.trim()) localStorage.setItem(LAST_PEM_KEY, pem);
      else localStorage.removeItem(LAST_PEM_KEY);
    } catch {
      // best-effort persistence
    }
  }, [pem]);

  // Prefer the pasted input; fall back to the certificate loaded in the store.
  const source = pem.trim() || leafCert?.pem || '';
  const result = useMemo(() => {
    if (!source) return null;
    return describeCertificateFromPEM(source);
  }, [source]);

  return (
    <div className="h-full overflow-auto pr-2">
      <div className="mb-4">
        <label className="text-xs text-zinc-500 mb-1 block">
          粘贴证书 PEM（留空则使用已加载的证书）
        </label>
        <textarea
          value={pem}
          onChange={(e) => setPem(e.target.value)}
          placeholder="-----BEGIN CERTIFICATE-----"
          spellCheck={false}
          className="w-full h-28 bg-zinc-900 border border-zinc-800 rounded-lg p-2 text-xs font-mono text-zinc-300 resize-none focus:outline-none focus:border-emerald-500/50"
        />
      </div>

      {!result && (
        <div className="flex flex-col items-center justify-center py-12 text-zinc-500">
          <ScrollText className="w-12 h-12 mb-4 opacity-30" />
          <p className="text-sm">粘贴或加载证书以查看详情</p>
        </div>
      )}

      {result && result.ok === false && (
        <div className="p-3 rounded-lg border bg-red-500/10 border-red-500/30 flex items-start gap-3">
          <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-medium text-red-400">证书解析失败</p>
            <p className="text-xs text-red-400/80 mt-0.5 break-all">{result.error}</p>
          </div>
        </div>
      )}

      {result && result.ok === true && <CertificateSummaryView summary={result.summary} />}
    </div>
  );
}

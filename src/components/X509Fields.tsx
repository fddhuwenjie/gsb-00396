import { Shield, Calendar, User, Building2, Key, FileText, Hash, Globe, Lock, AlertTriangle, CheckCircle2 } from 'lucide-react';
import { useCertificateStore } from '@/store/certificateStore';
import { lookupOID, oidToLongName } from '@/utils/oids';
import { Extension } from '@/utils/x509';

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
  if (match) {
    return match[1].toUpperCase();
  }
  return serial;
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

function DNFields({ title, dn }: { title: string; dn: Record<string, string[]> }) {
  const entries = Object.entries(dn);
  return (
    <div className="space-y-1">
      <span className="text-zinc-500 text-xs">{title}</span>
      {entries.map(([oid, values]) => (
        <div key={oid} className="flex gap-3 text-xs ml-3">
          <span className="text-emerald-500 w-20 flex-shrink-0 font-mono">
            {oidToLongName(oid)}
          </span>
          <span className="text-zinc-300">{values.join(', ')}</span>
        </div>
      ))}
    </div>
  );
}

function ExtensionItem({ ext }: { ext: Extension }) {
  const renderValue = () => {
    switch (ext.oid) {
      case '2.5.29.19': {
        const bc = ext.parsed as { ca: boolean; pathLen?: number } | undefined;
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
          <div className="flex flex-wrap gap-2">
            {usages.map((u) => (
              <span
                key={u}
                className="text-xs px-2 py-0.5 bg-zinc-800 rounded text-zinc-300"
              >
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
              <div key={u} className="text-xs text-zinc-300 font-mono">
                {u}
              </div>
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
                <span className="text-zinc-300 font-mono">{entry.value}</span>
              </div>
            ))}
          </div>
        );
      }
      case '2.5.29.35':
      case '2.5.29.14': {
        const ki = (ext.parsed as { keyIdentifier?: string })?.keyIdentifier || ext.value;
        return (
          <div className="text-xs font-mono text-zinc-300 break-all">
            {typeof ki === 'string' && ki.match(/.{1,2}/g)?.join(':') || ki}
          </div>
        );
      }
      case '2.5.29.31': {
        const dps = (ext.parsed as { distributionPoints?: string[] })?.distributionPoints || [];
        return (
          <div className="space-y-1">
            {dps.map((dp, i) => (
              <div key={i} className="text-xs text-zinc-300 font-mono break-all">
                {dp}
              </div>
            ))}
          </div>
        );
      }
      case '1.3.6.1.5.5.7.1.1': {
        const aia = ext.parsed as { entries?: { method: string; location: string }[] } | undefined;
        return (
          <div className="space-y-1">
            {aia?.entries?.map((entry, i) => (
              <div key={i} className="text-xs">
                <span className="text-zinc-400">{entry.method}: </span>
                <span className="text-zinc-300 font-mono">{entry.location}</span>
              </div>
            ))}
          </div>
        );
      }
      default:
        return (
          <div className="text-xs font-mono text-zinc-400 break-all">
            {ext.value}
          </div>
        );
    }
  };

  return (
    <div className="py-2 border-b border-zinc-800/50 last:border-b-0">
      <div className="flex items-center gap-2 mb-1">
        <span className="text-sm font-medium text-zinc-200">{ext.name}</span>
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

export default function X509Fields() {
  const { leafCert, verifyResult, runSelfVerify, isVerifying } = useCertificateStore();

  if (!leafCert) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500">
        <Shield className="w-12 h-12 mb-4 opacity-30" />
        <p className="text-sm">请先加载证书以查看 X.509 字段</p>
      </div>
    );
  }

  const fields = leafCert.fields;
  const isValid = verifyResult?.valid;

  return (
    <div className="h-full overflow-auto pr-2">
      {verifyResult && (
        <div
          className={`mb-4 p-3 rounded-lg border flex items-center gap-3 ${
            isValid
              ? 'bg-emerald-500/10 border-emerald-500/30'
              : 'bg-red-500/10 border-red-500/30'
          }`}
        >
          {isValid ? (
            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
          ) : (
            <AlertTriangle className="w-5 h-5 text-red-400" />
          )}
          <div>
            <p
              className={`text-sm font-medium ${
                isValid ? 'text-emerald-400' : 'text-red-400'
              }`}
            >
              {isValid ? '自签名验证通过' : '自签名验证失败'}
            </p>
            {verifyResult.error && (
              <p className="text-xs text-red-400/80 mt-0.5">{verifyResult.error}</p>
            )}
          </div>
        </div>
      )}

      {!verifyResult && (
        <button
          onClick={runSelfVerify}
          disabled={isVerifying}
          className="mb-4 w-full py-2 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-sm transition-colors disabled:opacity-50"
        >
          {isVerifying ? '验证中...' : '运行自签名验证'}
        </button>
      )}

      <Section icon={FileText} title="基本信息">
        <Field label="版本" value={`v${fields.version} (0x${(fields.version - 1).toString(16)})`} />
        <Field label="序列号" value={formatSerial(fields.serialNumber)} mono />
        <Field label="签名算法" value={`${fields.signatureAlgorithm.name} (${fields.signatureAlgorithm.oid})`} mono />
      </Section>

      <Section icon={Building2} title="颁发者">
        <DNFields title="" dn={fields.issuer} />
      </Section>

      <Section icon={Calendar} title="有效期">
        <Field label="生效时间" value={formatDate(fields.validity.notBefore)} />
        <Field label="过期时间" value={formatDate(fields.validity.notAfter)} />
      </Section>

      <Section icon={User} title="主题">
        <DNFields title="" dn={fields.subject} />
      </Section>

      <Section icon={Key} title="公钥信息">
        <Field label="算法" value={`${fields.subjectPublicKeyInfo.algorithm.name} (${fields.subjectPublicKeyInfo.algorithm.oid})`} mono />
        {fields.subjectPublicKeyInfo.keySize && (
          <Field label="密钥长度" value={`${fields.subjectPublicKeyInfo.keySize} bit`} />
        )}
        {fields.subjectPublicKeyInfo.curve && (
          <Field label="曲线" value={fields.subjectPublicKeyInfo.curve} />
        )}
      </Section>

      <Section icon={Hash} title="扩展字段">
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

      <Section icon={Lock} title="签名值">
        <div className="text-xs font-mono text-zinc-400 break-all">
          {Array.from(leafCert.signatureRaw.slice(0, 64))
            .map((b) => b.toString(16).padStart(2, '0'))
            .join(' ')}
          {leafCert.signatureRaw.length > 64 ? '...' : ''}
          <span className="text-zinc-600 ml-2">({leafCert.signatureRaw.length} bytes)</span>
        </div>
      </Section>
    </div>
  );
}

import { Hexagon, Shield, Link, Terminal, FileKey, Github, Moon, Sun, Sparkles, Ban } from 'lucide-react';
import { cn } from '@/lib/utils';
import CertificateInput from '@/components/CertificateInput';
import ASN1Tree from '@/components/ASN1Tree';
import X509Fields from '@/components/X509Fields';
import ChainValidator from '@/components/ChainValidator';
import OpenSSLExport from '@/components/OpenSSLExport';
import CSRGenerator from '@/components/CSRGenerator';
import CRLParser from '@/components/CRLParser';
import { useCertificateStore, TabType } from '@/store/certificateStore';
import { useTheme } from '@/hooks/useTheme';

const tabs: { id: TabType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
  { id: 'x509', label: 'X.509 字段', icon: Shield },
  { id: 'asn1', label: 'ASN.1 树', icon: Hexagon },
  { id: 'chain', label: '链验证', icon: Link },
  { id: 'openssl', label: 'OpenSSL 输出', icon: Terminal },
  { id: 'csr', label: '生成 CSR', icon: Sparkles },
  { id: 'crl', label: 'CRL 解析', icon: Ban },
];

export default function Home() {
  const { activeTab, setActiveTab } = useCertificateStore();
  const { isDark, toggleTheme } = useTheme();

  const renderContent = () => {
    switch (activeTab) {
      case 'asn1':
        return <ASN1Tree />;
      case 'x509':
        return <X509Fields />;
      case 'chain':
        return <ChainValidator />;
      case 'openssl':
        return <OpenSSLExport />;
      case 'csr':
        return <CSRGenerator />;
      case 'crl':
        return <CRLParser />;
      default:
        return null;
    }
  };

  const showSidebar = ['x509', 'asn1', 'chain', 'openssl'].includes(activeTab);

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex flex-col">
      <header className="border-b border-zinc-800 bg-zinc-900/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center">
              <FileKey className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-base font-bold text-zinc-100">CertScope</h1>
              <p className="text-[11px] text-zinc-500">浏览器内 X.509 证书解析与验证</p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={toggleTheme}
              className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors"
              title={isDark ? '切换亮色' : '切换暗色'}
            >
              {isDark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            </button>
            <a
              href="https://github.com"
              target="_blank"
              rel="noopener noreferrer"
              className="p-2 rounded-lg hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 transition-colors"
              title="GitHub"
            >
              <Github className="w-4 h-4" />
            </a>
          </div>
        </div>
      </header>

      <main className="flex-1 max-w-7xl w-full mx-auto px-4 py-4 flex flex-col lg:flex-row gap-4 overflow-hidden">
        {showSidebar && (
          <aside className="lg:w-80 flex-shrink-0 flex flex-col lg:h-[calc(100vh-80px)] lg:sticky lg:top-20">
            <div className="bg-zinc-900/50 rounded-xl border border-zinc-800 p-4 flex-1 overflow-auto">
              <CertificateInput />
            </div>
          </aside>
        )}

        <section className={cn('flex-1 min-w-0 flex flex-col overflow-hidden', !showSidebar && 'w-full')}>
          <div className="bg-zinc-900/50 rounded-xl border border-zinc-800 flex flex-col h-[calc(100vh-80px)] overflow-hidden">
            <nav className="flex gap-1 p-2 border-b border-zinc-800 overflow-x-auto">
              {tabs.map((tab) => {
                const Icon = tab.icon;
                const isActive = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    onClick={() => setActiveTab(tab.id)}
                    className={cn(
                      'flex items-center gap-2 px-4 py-2 text-xs font-medium rounded-lg transition-all whitespace-nowrap',
                      isActive
                        ? tab.id === 'csr'
                          ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30'
                          : tab.id === 'crl'
                          ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                          : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                        : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-800/50 border border-transparent'
                    )}
                  >
                    <Icon className="w-4 h-4" />
                    {tab.label}
                  </button>
                );
              })}
            </nav>

            <div className="flex-1 overflow-hidden p-4">
              {renderContent()}
            </div>
          </div>
        </section>
      </main>

      <footer className="border-t border-zinc-800 bg-zinc-900/30 py-2">
        <div className="max-w-7xl mx-auto px-4 flex items-center justify-between text-[11px] text-zinc-500">
          <span>纯本地解析，数据不出浏览器</span>
          <span>基于 Web Crypto API · 自实现 ASN.1 解析</span>
        </div>
      </footer>
    </div>
  );
}

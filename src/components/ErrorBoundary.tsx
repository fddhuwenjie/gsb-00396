import { Component, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error) {
    this.setState({ hasError: true, error });
  }

  reset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex flex-col items-center justify-center h-full p-8">
          <div className="w-full max-w-lg bg-red-500/10 border border-red-500/30 rounded-lg p-5">
            <div className="flex items-center gap-2 mb-3">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h2 className="text-sm font-semibold text-red-400">页面渲染出错</h2>
            </div>
            <p className="text-xs text-red-300/80 mb-1">
              证书详情页面在渲染时遇到未预期的错误。这通常意味着证书数据结构异常。
            </p>
            {this.state.error && (
              <pre className="mt-3 text-[11px] font-mono text-red-300/70 bg-red-950/40 rounded p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.reset}
              className="mt-4 px-4 py-2 bg-red-500/20 hover:bg-red-500/30 text-red-300 rounded-md text-xs transition-colors"
            >
              重试
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

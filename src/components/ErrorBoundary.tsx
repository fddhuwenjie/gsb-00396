import { Component, ReactNode } from 'react';
import { AlertTriangle } from 'lucide-react';

interface Props {
  children: ReactNode;
}

interface State {
  error: Error | null;
}

export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex flex-col items-center justify-center h-full p-6 text-center">
          <AlertTriangle className="w-10 h-10 text-red-400 mb-3" />
          <h2 className="text-sm font-semibold text-red-400 mb-1">页面渲染出错</h2>
          <p className="text-xs text-zinc-400 break-all max-w-lg">
            {this.state.error.message}
          </p>
          <button
            onClick={() => this.setState({ error: null })}
            className="mt-4 px-4 py-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 rounded-lg text-xs transition-colors"
          >
            重试
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

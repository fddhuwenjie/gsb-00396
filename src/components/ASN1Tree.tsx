import { useState, useMemo } from 'react';
import { ChevronRight, ChevronDown, Hexagon } from 'lucide-react';
import { cn } from '@/lib/utils';
import { ASN1Node, getTagName } from '@/utils/asn1';
import { useCertificateStore } from '@/store/certificateStore';

function getTagColor(tag: number, tagClass: string): string {
  if (tagClass !== 'universal') return 'text-zinc-400';
  switch (tag) {
    case 0x30: // SEQUENCE
      return 'text-sky-400';
    case 0x31: // SET
      return 'text-sky-300';
    case 0x02: // INTEGER
      return 'text-amber-400';
    case 0x06: // OID
      return 'text-emerald-400';
    case 0x04: // OCTET STRING
      return 'text-purple-400';
    case 0x03: // BIT STRING
      return 'text-purple-300';
    case 0x17: // UTCTime
    case 0x18: // GeneralizedTime
      return 'text-pink-400';
    case 0x0c: // UTF8String
    case 0x13: // PrintableString
    case 0x16: // IA5String
      return 'text-green-400';
    default:
      return 'text-zinc-400';
  }
}

function formatHex(n: number): string {
  return '0x' + n.toString(16).padStart(2, '0');
}

function TreeNode({
  node,
  depth = 0,
  defaultExpanded = false,
}: {
  node: ASN1Node;
  depth?: number;
  defaultExpanded?: boolean;
}) {
  const [expanded, setExpanded] = useState(defaultExpanded);
  const hasChildren = node.constructed && node.children && node.children.length > 0;
  const tagColor = getTagColor(node.tag, node.tagClass);

  const valuePreview = useMemo(() => {
    if (!node.constructed && node.parsedValue) {
      const val = node.parsedValue;
      if (val.length > 80) {
        return val.slice(0, 80) + '...';
      }
      return val;
    }
    return null;
  }, [node]);

  return (
    <div>
      <div
        className={cn(
          'flex items-center gap-1 py-1 px-2 hover:bg-zinc-800/50 rounded font-mono text-xs cursor-pointer select-none',
          depth === 0 && 'font-medium'
        )}
        style={{ paddingLeft: `${depth * 16 + 8}px` }}
        onClick={() => hasChildren && setExpanded(!expanded)}
      >
        {hasChildren ? (
          expanded ? (
            <ChevronDown className="w-3.5 h-3.5 text-zinc-500" />
          ) : (
            <ChevronRight className="w-3.5 h-3.5 text-zinc-500" />
          )
        ) : (
          <span className="w-3.5 h-3.5" />
        )}
        <Hexagon
            className={cn('w-3 h-3', tagColor)}
          />
        <span className={cn('font-medium', tagColor)}>
          {getTagName(node)}
        </span>
        <span className="text-zinc-600 text-[10px]">
          [{formatHex(node.tag)}]
        </span>
        <span className="text-zinc-500 text-[10px]">
          len: {node.length}
        </span>
        <span className="text-zinc-600 text-[10px]">
          @ offset {node.offset}
        </span>
        {valuePreview !== null && (
          <span className="text-zinc-300 ml-2 truncate" title={node.parsedValue}>
            : {valuePreview}
          </span>
        )}
      </div>
      {hasChildren && expanded && (
        <div>
          {node.children!.map((child, i) => (
            <TreeNode key={i} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function hexDump(data: Uint8Array, bytesPerLine: number = 16): string[] {
  const lines: string[] = [];
  for (let i = 0; i < data.length; i += bytesPerLine) {
    const chunk = data.slice(i, Math.min(i + bytesPerLine, data.length));
    let hex = '';
    let ascii = '';
    for (let j = 0; j < chunk.length; j++) {
      hex += chunk[j].toString(16).padStart(2, '0') + ' ';
      ascii += chunk[j] >= 32 && chunk[j] < 127 ? String.fromCharCode(chunk[j]) : '.';
    }
    const offset = i.toString(16).padStart(4, '0');
    lines.push(`${offset}  ${hex.padEnd(bytesPerLine * 3 - 1, ' ')}  ${ascii}`);
  }
  return lines;
}

export default function ASN1Tree() {
  const { leafCert } = useCertificateStore();

  if (!leafCert) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500">
        <Hexagon className="w-12 h-12 mb-4 opacity-30" />
        <p className="text-sm">请先加载证书以查看 ASN.1 结构</p>
      </div>
    );
  }

  const hexLines = hexDump(leafCert.der);

  return (
    <div className="flex h-full gap-4 overflow-hidden">
      <div className="flex-1 min-w-0 flex flex-col overflow-hidden">
      <h3 className="text-sm font-semibold text-zinc-200 mb-3 flex items-center gap-2">
        <Hexagon className="w-4 h-4 text-sky-400" />
          ASN.1 结构树
      </h3>
      <div className="flex-1 overflow-auto bg-zinc-950/50 rounded-lg border border-zinc-800 p-2 font-mono text-xs">
        <TreeNode node={leafCert.asn1} defaultExpanded={true} />
      </div>
    </div>

      <div className="w-80 flex-shrink-0 flex flex-col overflow-hidden">
        <h3 className="text-sm font-semibold text-zinc-200 mb-3">
          HEX 数据
        </h3>
        <div className="flex-1 overflow-auto bg-zinc-950/50 rounded-lg border border-zinc-800 p-3 font-mono text-[11px] text-zinc-400 whitespace-pre">
          {hexLines.map((line, i) => (
            <div key={i}>{line}</div>
          ))}
        </div>
      </div>
    </div>
  );
}

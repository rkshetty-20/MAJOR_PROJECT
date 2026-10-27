// Packet analysis view: per-packet table, hex-dump viewer, protocol dissection
// and a flow timeline. Self-contained tabbed panel over one analysis result.
import React, { useMemo, useState } from 'react';
import {
  Table2,
  Binary,
  GitBranch,
  Activity,
  ChevronLeft,
  ChevronRight,
  Search,
} from 'lucide-react';
import type { IdsAnalysis, PacketRecord } from './types';
import { Card } from './primitives';
import { Button } from '../ui';

type Tab = 'table' | 'timeline' | 'dissection';

export const PacketAnalysisView: React.FC<{ analysis: IdsAnalysis }> = ({ analysis }) => {
  const [tab, setTab] = useState<Tab>('table');
  const [selectedIdx, setSelectedIdx] = useState<number>(0);
  const [protocolFilter, setProtocolFilter] = useState<string>('ALL');
  const [query, setQuery] = useState<string>('');

  const packets = analysis.packets;
  const suspicious = useMemo(() => new Set(analysis.packet_analysis.suspicious_indices), [analysis]);

  const protocols = useMemo(() => {
    const set = new Set(packets.map((p) => p.protocol));
    return ['ALL', ...Array.from(set)];
  }, [packets]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return packets.filter((p) => {
      if (protocolFilter !== 'ALL' && p.protocol !== protocolFilter) return false;
      if (!q) return true;
      return (
        p.src_ip.toLowerCase().includes(q) ||
        p.dst_ip.toLowerCase().includes(q) ||
        p.payload_text.toLowerCase().includes(q) ||
        String(p.dst_port).includes(q)
      );
    });
  }, [packets, protocolFilter, query]);

  const selected: PacketRecord | undefined = filtered[selectedIdx] ?? filtered[0];

  return (
    <Card
      title="Packet Analysis"
      icon={<Binary className="w-4 h-4" />}
      right={
        <div className="flex items-center gap-1 bg-app p-1 rounded-lg border border-line-strong" role="tablist" aria-label="Packet analysis views">
          <TabButton active={tab === 'table'} onClick={() => setTab('table')} icon={<Table2 className="w-3.5 h-3.5" />} label="Table" />
          <TabButton active={tab === 'timeline'} onClick={() => setTab('timeline')} icon={<Activity className="w-3.5 h-3.5" />} label="Timeline" />
          <TabButton active={tab === 'dissection'} onClick={() => setTab('dissection')} icon={<GitBranch className="w-3.5 h-3.5" />} label="Dissection" />
        </div>
      }
    >
      {tab === 'table' && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-ink-faint absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                value={query}
                onChange={(e) => { setQuery(e.target.value); setSelectedIdx(0); }}
                placeholder="Filter IP / port / payload..."
                aria-label="Filter packets by IP, port, or payload"
                className="bg-app border border-line-strong rounded-lg pl-8 pr-3 py-1.5 text-xs text-ink w-56 focus:outline-none focus:ring-2 focus:ring-accent/40"
              />
            </div>
            <select
              value={protocolFilter}
              onChange={(e) => { setProtocolFilter(e.target.value); setSelectedIdx(0); }}
              aria-label="Filter packets by protocol"
              className="bg-app border border-line-strong rounded-lg px-3 py-1.5 text-xs text-ink focus:outline-none focus:ring-2 focus:ring-accent/40"
            >
              {protocols.map((p) => (
                <option key={p} value={p}>{p === 'ALL' ? 'All protocols' : p}</option>
              ))}
            </select>
            <span className="text-[11px] text-ink-faint ml-auto">{filtered.length} / {packets.length} packets</span>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            {/* Table */}
            <div className="overflow-auto max-h-[420px] rounded-lg border border-line">
              <table className="w-full text-[11px]">
                <caption className="sr-only">Captured packets for this analysis, ordered by arrival.</caption>
                <thead className="bg-app text-ink-muted sticky top-0 z-10">
                  <tr className="text-left">
                    <th scope="col" className="px-2 py-2 font-semibold">#</th>
                    <th scope="col" className="px-2 py-2 font-semibold">Time</th>
                    <th scope="col" className="px-2 py-2 font-semibold">Proto</th>
                    <th scope="col" className="px-2 py-2 font-semibold">Source → Dest</th>
                    <th scope="col" className="px-2 py-2 font-semibold">Flags</th>
                    <th scope="col" className="px-2 py-2 font-semibold text-right">TTL</th>
                    <th scope="col" className="px-2 py-2 font-semibold text-right">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((p, i) => {
                    const isSel = selected?.index === p.index;
                    const isSusp = suspicious.has(p.index);
                    return (
                      <tr
                        key={p.index}
                        onClick={() => setSelectedIdx(i)}
                        aria-selected={isSel}
                        className={`cursor-pointer border-t border-line transition-colors duration-base ${
                          isSel ? 'bg-accent/10' : 'hover:bg-elevated/40'
                        }`}
                      >
                        <td className="px-2 py-1.5 font-mono text-ink-faint">{p.index}</td>
                        <td className="px-2 py-1.5 font-mono text-ink-muted whitespace-nowrap">{p.timestamp.split(' ')[1] ?? p.timestamp}</td>
                        <td className="px-2 py-1.5">
                          <span className="px-1.5 py-0.5 rounded bg-elevated text-ink-soft font-mono">{p.protocol}</span>
                        </td>
                        <td className="px-2 py-1.5 font-mono text-ink-soft whitespace-nowrap">
                          {p.src_ip}:{p.src_port} <span className="text-ink-faint">→</span> {p.dst_ip}:{p.dst_port}
                        </td>
                        <td className="px-2 py-1.5 font-mono text-ink-muted">{p.flags}</td>
                        <td className="px-2 py-1.5 font-mono text-ink-muted text-right">{p.ttl}</td>
                        <td className="px-2 py-1.5 font-mono text-right">
                          <span
                            className={isSusp ? 'text-rose-400 font-bold' : 'text-ink-muted'}
                            title={isSusp ? 'Suspicious packet' : undefined}
                          >
                            {isSusp && <span aria-hidden>⚠ </span>}{p.size}B
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>

            {/* Detail: dissection + hex */}
            {selected ? (
              <PacketDetail packet={selected} suspicious={suspicious.has(selected.index)} />
            ) : (
              <div className="text-xs text-ink-muted italic">No packets match the filter.</div>
            )}
          </div>

          {filtered.length > 0 && (
            <div className="flex items-center justify-end gap-2 pt-1">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedIdx((i) => Math.max(0, i - 1))}
                disabled={selectedIdx === 0}
                aria-label="Previous packet"
              >
                <ChevronLeft className="w-4 h-4" />
              </Button>
              <span className="text-[11px] font-mono text-ink-muted w-16 text-center">
                {selectedIdx + 1} / {filtered.length}
              </span>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedIdx((i) => Math.min(filtered.length - 1, i + 1))}
                disabled={selectedIdx >= filtered.length - 1}
                aria-label="Next packet"
              >
                <ChevronRight className="w-4 h-4" />
              </Button>
            </div>
          )}
        </div>
      )}

      {tab === 'timeline' && <FlowTimeline packets={filtered} suspicious={suspicious} onSelect={setSelectedIdx} selectedIndex={selected?.index} />}

      {tab === 'dissection' && <Dissection analysis={analysis} />}
    </Card>
  );
};

// ---------------------------------------------------------------------------
const PacketDetail: React.FC<{ packet: PacketRecord; suspicious: boolean }> = ({ packet, suspicious }) => (
  <div className="space-y-3">
    <div className="flex items-center justify-between">
      <span className="text-xs font-semibold text-ink-soft uppercase tracking-wider">
        Packet #{packet.index} Dissection
      </span>
      {suspicious && (
        <span className="text-[10px] px-2 py-0.5 rounded bg-rose-500/15 text-rose-300 border border-rose-500/30 font-semibold uppercase">
          Suspicious pattern
        </span>
      )}
    </div>

    <div className="grid grid-cols-2 gap-2 text-[11px]">
      <Field k="Protocol" v={packet.protocol} />
      <Field k="Timestamp" v={packet.timestamp} />
      <Field k="Source" v={`${packet.src_ip}:${packet.src_port}`} />
      <Field k="Destination" v={`${packet.dst_ip}:${packet.dst_port}`} />
      <Field k="TCP Flags" v={packet.flags} />
      <Field k="TTL" v={String(packet.ttl)} />
      <Field k="Size" v={`${packet.size} bytes`} />
      <Field k="Arrival (unix)" v={packet.unix_ts.toFixed(3)} />
    </div>

    {packet.payload_text && (
      <div>
        <div className="text-[10px] uppercase tracking-wider text-ink-faint mb-1 font-semibold">Payload Preview</div>
        <pre className="text-[11px] text-emerald-300/90 bg-app border border-line rounded-lg p-2.5 whitespace-pre-wrap break-all font-mono max-h-24 overflow-auto">
          {packet.payload_text}
        </pre>
      </div>
    )}

    <div>
      <div className="text-[10px] uppercase tracking-wider text-ink-faint mb-1 font-semibold">Hex Dump</div>
      <pre className="text-[10.5px] leading-relaxed text-ink-soft bg-app border border-line rounded-lg p-2.5 whitespace-pre overflow-auto max-h-48 font-mono">
        {packet.hex || <span className="text-ink-faint italic">No bytes captured.</span>}
      </pre>
    </div>
  </div>
);

const Field: React.FC<{ k: string; v: string }> = ({ k, v }) => (
  <div className="rounded-lg border border-line bg-app/60 px-2.5 py-1.5">
    <div className="text-[9px] uppercase tracking-wider text-ink-faint">{k}</div>
    <div className="text-ink font-mono truncate">{v}</div>
  </div>
);

// ---------------------------------------------------------------------------
const FlowTimeline: React.FC<{
  packets: PacketRecord[];
  suspicious: Set<number>;
  onSelect: (i: number) => void;
  selectedIndex?: number;
}> = ({ packets, suspicious, onSelect, selectedIndex }) => {
  if (packets.length < 2) return <div className="text-xs text-ink-muted italic">Not enough packets to render a timeline.</div>;
  const times = packets.map((p) => p.unix_ts);
  const t0 = Math.min(...times);
  const t1 = Math.max(...times);
  const span = t1 - t0 || 1;
  const sizeMax = Math.max(...packets.map((p) => p.size)) || 1;

  // Bucket packets into ~60 columns for a compact histogram + scatter.
  const buckets: PacketRecord[][] = Array.from({ length: 60 }, () => []);
  packets.forEach((p) => {
    const b = Math.min(59, Math.floor(((p.unix_ts - t0) / span) * 60));
    buckets[b].push(p);
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-[11px] text-ink-muted">
        <span>Arrival timeline · bar height = packet size · <span className="text-rose-400">red</span> = suspicious</span>
        <span className="font-mono">span {span.toFixed(2)}s</span>
      </div>
      <div className="flex items-end gap-[2px] h-40 bg-app border border-line rounded-lg p-3">
        {buckets.map((bucket, bi) => {
          if (bucket.length === 0) return <div key={bi} className="flex-1 h-[2px] bg-elevated/40 rounded" />;
          const maxSize = Math.max(...bucket.map((p) => p.size));
          const h = Math.max(6, (maxSize / sizeMax) * 100);
          const anySusp = bucket.some((p) => suspicious.has(p.index));
          const isSelected = bucket.some((p) => p.index === selectedIndex);
          return (
            <div
              key={bi}
              onClick={() => { const idx = packets.findIndex((p) => p.index === bucket[0].index); onSelect(idx); }}
              title={`${bucket.length} pk · ${bucket[0].protocol} · ${Math.round(maxSize)}B`}
              className="flex-1 rounded-t cursor-pointer transition-opacity hover:opacity-80"
              style={{
                height: `${h}%`,
                backgroundColor: isSelected ? '#818cf8' : anySusp ? '#fb7185' : '#4f46e5',
              }}
            />
          );
        })}
      </div>
      <div className="flex justify-between text-[10px] font-mono text-ink-faint">
        <span>t0 +0.00s</span>
        <span>t0 +{(span / 2).toFixed(2)}s</span>
        <span>t0 +{span.toFixed(2)}s</span>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
const Dissection: React.FC<{ analysis: IdsAnalysis }> = ({ analysis }) => {
  const { protocol_breakdown, port_breakdown, flag_breakdown, size_stats, total_bytes } = analysis.packet_analysis;
  const total = Object.values(protocol_breakdown).reduce((a, b) => a + b, 0) || 1;

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
      <BreakdownList title="Protocol Distribution" data={protocol_breakdown} total={total} color="#6366f1" />
      <BreakdownList title="TCP Flag Distribution" data={flag_breakdown} total={total} color="#c084fc" />
      <BreakdownList title="Top Destination Ports" data={port_breakdown} total={total} color="#38bdf8" />
      <div>
        <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2">Size Statistics</div>
        <div className="grid grid-cols-2 gap-2 text-[11px]">
          <Field k="Min" v={`${size_stats.min ?? 0} B`} />
          <Field k="Max" v={`${size_stats.max ?? 0} B`} />
          <Field k="Mean" v={`${size_stats.mean ?? 0} B`} />
          <Field k="Total" v={`${total_bytes.toLocaleString()} B`} />
        </div>
      </div>
    </div>
  );
};

const BreakdownList: React.FC<{ title: string; data: Record<string, number>; total: number; color: string }> = ({
  title,
  data,
  total,
  color,
}) => {
  const entries = Object.entries(data).sort((a, b) => b[1] - a[1]).slice(0, 8);
  return (
    <div>
      <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted mb-2">{title}</div>
      <div className="space-y-1.5">
        {entries.length === 0 && <div className="text-xs text-ink-muted italic">No data.</div>}
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-center gap-2">
            <span className="w-24 shrink-0 text-[11px] font-mono text-ink-soft truncate">{k}</span>
            <div className="flex-1 h-2 bg-elevated rounded-full overflow-hidden">
              <div className="h-full rounded-full" style={{ width: `${(v / total) * 100}%`, backgroundColor: color }} />
            </div>
            <span className="w-8 text-right text-[11px] font-mono text-ink-muted">{v}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

const TabButton: React.FC<{ active: boolean; onClick: () => void; icon: React.ReactNode; label: string }> = ({
  active,
  onClick,
  icon,
  label,
}) => (
  <button
    role="tab"
    aria-selected={active}
    onClick={onClick}
    className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium transition-all duration-base focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
      active ? 'bg-accent text-white' : 'text-ink-muted hover:text-ink'
    }`}
  >
    {icon}
    {label}
  </button>
);

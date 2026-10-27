import React, { useState } from 'react';
import { Activity, ShieldAlert, ShieldCheck, Key, Globe, Server, User, Link as LinkIcon, Network, HelpCircle } from 'lucide-react';

interface NodeData {
  id: string;
  type: 'phishing' | 'domain' | 'ip' | 'user' | 'host' | 'auth' | 'network' | 'detection' | 'incident';
  label: string;
  details: Record<string, any>;
}

interface EdgeData {
  id: string;
  sourceId: string;
  targetId: string;
  label: string;
  reason: string;
  type: 'direct' | 'rule' | 'hypothesized';
}

interface Props {
  nodes: NodeData[];
  edges: EdgeData[];
}

const typeConfig = {
  phishing: { icon: Globe, color: 'text-amber-400', bg: 'bg-amber-500/10', border: 'border-amber-500/30' },
  domain: { icon: Globe, color: 'text-sky-400', bg: 'bg-sky-500/10', border: 'border-sky-500/30' },
  ip: { icon: Network, color: 'text-sky-400', bg: 'bg-sky-500/10', border: 'border-sky-500/30' },
  user: { icon: User, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/30' },
  host: { icon: Server, color: 'text-indigo-400', bg: 'bg-indigo-500/10', border: 'border-indigo-500/30' },
  auth: { icon: Key, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
  network: { icon: Activity, color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30' },
  detection: { icon: ShieldAlert, color: 'text-rose-400', bg: 'bg-rose-500/10', border: 'border-rose-500/30' },
  incident: { icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30' },
};

export const InvestigationRelationshipGraph: React.FC<Props> = ({ nodes, edges }) => {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  if (nodes.length === 0) {
    return (
      <div className="p-8 bg-slate-900 border border-slate-800 rounded-xl text-center text-slate-400">
        No entities available to form a relationship graph.
      </div>
    );
  }

  const selectedNode = nodes.find(n => n.id === selectedNodeId);
  const selectedEdge = edges.find(e => e.id === selectedEdgeId);

  return (
    <div className="flex flex-col lg:flex-row gap-6">
      <div className="flex-1 bg-slate-900 border border-slate-800 rounded-xl p-6 overflow-hidden flex flex-col">
        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
          Entity Relationships
        </h3>
        
        {/* Simple List-based Alternative to a complex SVG graph */}
        <div className="space-y-4 max-h-[400px] overflow-y-auto custom-scrollbar pr-2">
          {edges.length > 0 ? edges.map(edge => {
            const source = nodes.find(n => n.id === edge.sourceId);
            const target = nodes.find(n => n.id === edge.targetId);
            if (!source || !target) return null;
            
            const SourceIcon = typeConfig[source.type].icon;
            const TargetIcon = typeConfig[target.type].icon;

            return (
              <div key={edge.id} className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 bg-slate-950 rounded-lg border border-slate-800 relative">
                
                <button onClick={() => setSelectedNodeId(source.id)} className={`flex items-center gap-3 text-left w-full sm:w-1/3 p-2 rounded-lg hover:bg-slate-800 transition-colors ${selectedNodeId === source.id ? 'ring-2 ring-indigo-500' : ''}`}>
                  <div className={`p-2 rounded-lg ${typeConfig[source.type].bg} ${typeConfig[source.type].color}`}>
                    <SourceIcon className="w-5 h-5" />
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-xs text-slate-500 uppercase">{source.type}</div>
                    <div className="text-sm font-bold text-white truncate">{source.label}</div>
                  </div>
                </button>

                <button 
                  onClick={() => setSelectedEdgeId(edge.id)} 
                  className={`flex-1 flex flex-col items-center justify-center group focus:outline-none ${selectedEdgeId === edge.id ? 'text-indigo-400' : 'text-slate-500'}`}
                >
                  <div className="text-xs font-mono mb-1 bg-slate-900 px-2 py-0.5 rounded-full border border-slate-700 group-hover:border-indigo-500 group-hover:text-indigo-400 transition-colors">
                    {edge.label}
                  </div>
                  <div className={`w-full h-px ${edge.type === 'hypothesized' ? 'border-t border-dashed border-slate-600' : 'bg-slate-700'}`}></div>
                </button>

                <button onClick={() => setSelectedNodeId(target.id)} className={`flex items-center gap-3 text-left w-full sm:w-1/3 p-2 rounded-lg hover:bg-slate-800 transition-colors ${selectedNodeId === target.id ? 'ring-2 ring-indigo-500' : ''}`}>
                  <div className={`p-2 rounded-lg ${typeConfig[target.type].bg} ${typeConfig[target.type].color}`}>
                    <TargetIcon className="w-5 h-5" />
                  </div>
                  <div className="overflow-hidden">
                    <div className="text-xs text-slate-500 uppercase">{target.type}</div>
                    <div className="text-sm font-bold text-white truncate">{target.label}</div>
                  </div>
                </button>

              </div>
            );
          }) : (
            <div className="flex flex-wrap gap-4">
              {nodes.map(node => {
                const Icon = typeConfig[node.type].icon;
                return (
                  <button key={node.id} onClick={() => setSelectedNodeId(node.id)} className={`flex items-center gap-3 p-3 rounded-lg border bg-slate-950 transition-colors ${selectedNodeId === node.id ? 'border-indigo-500 ring-1 ring-indigo-500' : 'border-slate-800 hover:border-slate-700'}`}>
                    <div className={`p-2 rounded-lg ${typeConfig[node.type].bg} ${typeConfig[node.type].color}`}>
                      <Icon className="w-5 h-5" />
                    </div>
                    <div className="text-left">
                      <div className="text-xs text-slate-500 uppercase">{node.type}</div>
                      <div className="text-sm font-bold text-white">{node.label}</div>
                    </div>
                  </button>
                )
              })}
            </div>
          )}
        </div>
      </div>

      <div className="w-full lg:w-80 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col shadow-sm shrink-0">
        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4 border-b border-slate-800 pb-2">
          Details Panel
        </h3>
        {selectedNode ? (
          <div className="space-y-4 animate-fade-in">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${typeConfig[selectedNode.type].bg} ${typeConfig[selectedNode.type].color}`}>
                {React.createElement(typeConfig[selectedNode.type].icon, { className: 'w-6 h-6' })}
              </div>
              <div>
                <div className="text-xs text-slate-500 uppercase font-bold">{selectedNode.type}</div>
                <div className="text-base font-bold text-white break-all">{selectedNode.label}</div>
              </div>
            </div>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 space-y-2">
              {Object.entries(selectedNode.details).map(([key, value]) => (
                <div key={key}>
                  <span className="text-xs text-slate-500 uppercase">{key}:</span>{' '}
                  <span className="text-sm text-slate-300 font-mono break-all">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        ) : selectedEdge ? (
          <div className="space-y-4 animate-fade-in">
            <div className="flex items-center gap-3">
              <div className="p-2 bg-slate-800 text-slate-300 rounded-lg">
                <LinkIcon className="w-6 h-6" />
              </div>
              <div>
                <div className="text-xs text-slate-500 uppercase font-bold">Relationship</div>
                <div className="text-base font-bold text-white font-mono">{selectedEdge.label}</div>
              </div>
            </div>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <h4 className="text-xs font-bold text-slate-500 uppercase mb-1">Reason</h4>
              <p className="text-sm text-slate-300 leading-relaxed">{selectedEdge.reason}</p>
            </div>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
              <h4 className="text-xs font-bold text-slate-500 uppercase mb-1 flex items-center gap-1">
                <HelpCircle className="w-3 h-3" /> Association Type
              </h4>
              <p className="text-sm text-slate-300 capitalize">
                {selectedEdge.type === 'direct' ? 'Directly Observed Relationship' :
                 selectedEdge.type === 'rule' ? 'Deterministic Rule-Derived Association' :
                 'Hypothesized Association'}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex-1 flex flex-col items-center justify-center text-center text-slate-500 opacity-60">
            <Activity className="w-8 h-8 mb-3" />
            <p className="text-sm">Select a node or relationship edge to view details.</p>
          </div>
        )}
      </div>
    </div>
  );
};

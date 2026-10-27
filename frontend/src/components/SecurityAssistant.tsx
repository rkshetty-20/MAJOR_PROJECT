import React, { useState, useRef, useEffect } from 'react';
import { 
  ShieldAlert, 
  Send, 
  Trash2, 
  Sparkles, 
  AlertCircle, 
  Bot, 
  User, 
  Terminal,
  ShieldCheck,
  CheckCircle2,
  X,
  Square,
  RefreshCcw,
  Copy,
  Check
} from 'lucide-react';
import { streamChat } from '../api';

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  model?: string;
  status: 'streaming' | 'completed' | 'failed' | 'interrupted';
  error?: string;
}

const QUICK_PROMPTS_LEARNING = [
  "What is cybersecurity?",
  "Explain phishing.",
  "Brute force vs credential stuffing.",
  "What is Random Forest?"
];

const QUICK_PROMPTS_PROJECT = [
  "Why was this detection triggered?",
  "Show the evidence.",
  "Explain this risk score.",
  "Was adaptive ML involved?",
  "What should I investigate next?"
];

interface SecurityAssistantProps {
  externalContext?: Record<string, unknown> | null;
  externalPrompt?: string | null;
  onClearExternalContext?: () => void;
}

const MarkdownRenderer: React.FC<{ content: string }> = ({ content }) => {
  const codeBlockRegex = /(```[\s\S]*?(?:```|$))/g;
  const parts = content.split(codeBlockRegex);

  return (
    <div className="text-slate-300">
      {parts.map((part, index) => {
        if (part.startsWith('```')) {
          const lines = part.split('\n');
          const lang = lines[0].slice(3).trim();
          const hasClosing = part.endsWith('```') && part.length > 3;
          const code = lines.slice(1, hasClosing ? -1 : undefined).join('\n');
          
          return (
            <div key={index} className="my-3 rounded-md bg-[#020617] border border-slate-700/50 overflow-hidden shadow-sm">
              {lang && (
                <div className="px-3 py-1 text-[11px] font-semibold text-slate-400 bg-slate-800/50 border-b border-slate-700/50 uppercase tracking-wider">
                  {lang}
                </div>
              )}
              <pre className="p-3 text-[13px] font-mono text-slate-300 overflow-x-auto whitespace-pre-wrap">
                {code}
              </pre>
            </div>
          );
        }

        const lines = part.split('\n');
        return (
          <div key={index} className="space-y-1.5">
            {lines.map((line, lIndex) => {
              if (!line.trim()) return <div key={lIndex} className="h-1.5" />;
              
              let isHeading = false;
              let headingLevel = 0;
              if (line.startsWith('### ')) { isHeading = true; headingLevel = 3; }
              else if (line.startsWith('## ')) { isHeading = true; headingLevel = 2; }
              else if (line.startsWith('# ')) { isHeading = true; headingLevel = 1; }

              const isBullet = line.trim().startsWith('- ') || line.trim().startsWith('* ');
              const numberMatch = line.match(/^(\s*\d+\.\s)/);

              let cleanLine = line;
              if (isHeading) cleanLine = line.replace(/^#+\s/, '');
              else if (isBullet) cleanLine = line.trim().slice(2);
              else if (numberMatch) cleanLine = line.slice(numberMatch[0].length);

              const inlineParts = cleanLine.split(/(\*\*.*?\*\*|`.*?`)/g);
              const contentNode = inlineParts.map((p, i) => {
                if (p.startsWith('**') && p.endsWith('**')) {
                  return <strong key={i} className="font-semibold text-slate-100">{p.slice(2, -2)}</strong>;
                }
                if (p.startsWith('`') && p.endsWith('`')) {
                  return <code key={i} className="bg-[#020617] border border-slate-700/50 px-1 py-0.5 rounded text-emerald-400 font-mono text-xs">{p.slice(1, -1)}</code>;
                }
                return p;
              });

              if (isHeading) {
                if (headingLevel === 1) return <h1 key={lIndex} className="text-lg font-bold text-white mt-5 mb-2">{contentNode}</h1>;
                if (headingLevel === 2) return <h2 key={lIndex} className="text-base font-bold text-slate-100 mt-4 mb-2">{contentNode}</h2>;
                return <h3 key={lIndex} className="text-sm font-bold text-slate-200 mt-3 mb-1">{contentNode}</h3>;
              }

              if (isBullet) {
                return (
                  <div key={lIndex} className="flex items-start text-[13px] leading-relaxed ml-1">
                    <span className="text-slate-500 mr-2 mt-0.5">•</span>
                    <div className="flex-1">{contentNode}</div>
                  </div>
                );
              } else if (numberMatch) {
                return (
                  <div key={lIndex} className="flex items-start text-[13px] leading-relaxed ml-1">
                    <span className="text-slate-500 font-mono text-[11px] mr-2 mt-1 min-w-[1.2rem]">{numberMatch[1].trim()}</span>
                    <div className="flex-1">{contentNode}</div>
                  </div>
                );
              }

              return <div key={lIndex} className="text-[13px] leading-relaxed">{contentNode}</div>;
            })}
          </div>
        );
      })}
    </div>
  );
};

export const SecurityAssistant: React.FC<SecurityAssistantProps> = ({
  externalContext,
  externalPrompt,
  onClearExternalContext,
}) => {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: 'init',
      role: 'assistant',
      content: "Hello! I am your FraudGuard Security Assistant, specialized in defensive cybersecurity, incident analysis, and intrusion detection. How can I assist your security investigation today?",
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      model: "FraudGuard Security Engine",
      status: 'completed'
    }
  ]);
  const [inputValue, setInputValue] = useState('');
  const [generationState, setGenerationState] = useState<'idle' | 'preparing' | 'waiting' | 'receiving'>('idle');
  const [abortController, setAbortController] = useState<AbortController | null>(null);
  const [attachContext, setAttachContext] = useState(false);
  const [activeTelemetry, setActiveTelemetry] = useState<Record<string, unknown> | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const messagesEndRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const lastProcessedPrompt = useRef<string | null>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, generationState]);

  useEffect(() => {
    if (externalContext) {
      setActiveTelemetry(externalContext);
      setAttachContext(true);
    }
  }, [externalContext]);

  useEffect(() => {
    if (externalPrompt && externalPrompt !== lastProcessedPrompt.current) {
      lastProcessedPrompt.current = externalPrompt;
      setAttachContext(true);
      handleSendMessage(externalPrompt, externalContext || activeTelemetry);
    }
  }, [externalPrompt, externalContext]);

  const handleSendMessage = async (textToSend?: string, contextOverride?: Record<string, unknown> | null) => {
    const rawText = textToSend !== undefined ? textToSend : inputValue;
    const trimmed = rawText.trim();
    if (!trimmed || generationState !== 'idle') return;

    const userTimestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    const userMsgId = `user-${Date.now()}`;
    const asstMsgId = `asst-${Date.now()}`;

    const userMessage: ChatMessage = {
      id: userMsgId,
      role: 'user',
      content: trimmed,
      timestamp: userTimestamp,
      status: 'completed'
    };

    const assistantMessage: ChatMessage = {
      id: asstMsgId,
      role: 'assistant',
      content: "",
      timestamp: userTimestamp,
      status: 'streaming'
    };

    setMessages(prev => [...prev, userMessage, assistantMessage]);
    setInputValue('');
    setGenerationState('waiting');
    
    const controller = new AbortController();
    setAbortController(controller);

    try {
      // Build history for API
      const apiHistory = messages.filter(m => m.status === 'completed' && m.id !== 'init').map(m => ({
        role: m.role,
        content: m.content
      }));

      const contextToSend = attachContext || contextOverride
        ? (contextOverride || activeTelemetry)
        : null;

      const payload = {
        message: trimmed,
        conversation_history: apiHistory,
        security_context: contextToSend,
      };

      await streamChat(
        payload,
        {
          onMeta: (meta) => {
            setGenerationState('receiving');
            setMessages(prev => prev.map(m => 
              m.id === asstMsgId ? { ...m, model: meta.model } : m
            ));
          },
          onDelta: (text) => {
            setGenerationState(prev => prev !== 'receiving' ? 'receiving' : prev);
            setMessages(prev => prev.map(m => 
              m.id === asstMsgId ? { ...m, content: m.content + text } : m
            ));
          },
          onError: (errorMsg) => {
            setMessages(prev => prev.map(m => {
              if (m.id === asstMsgId) {
                // If we already have some content, it's interrupted
                const status = m.content.length > 0 ? 'interrupted' : 'failed';
                return { ...m, status, error: errorMsg };
              }
              return m;
            }));
          },
          onDone: () => {
            setGenerationState('idle');
            setAbortController(null);
            setMessages(prev => prev.map(m => 
              (m.id === asstMsgId && m.status === 'streaming') ? { ...m, status: 'completed' } : m
            ));
          }
        },
        controller.signal
      );
    } catch (err) {
      setGenerationState('idle');
      setAbortController(null);
    }
  };

  const handleStopGeneration = () => {
    if (abortController) {
      abortController.abort();
      setAbortController(null);
      setGenerationState('idle');
    }
  };

  const handleRetry = (msgIndex: number) => {
    // Find the user message before this assistant message
    const userMsg = messages[msgIndex - 1];
    if (userMsg && userMsg.role === 'user') {
      // Remove this failed message and all after
      setMessages(prev => prev.slice(0, msgIndex - 1));
      handleSendMessage(userMsg.content);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSendMessage();
    }
  };

  const handleClearChat = () => {
    setMessages([
      {
        id: 'init-cleared',
        role: 'assistant',
        content: "Conversation history cleared. How can I help you with your cybersecurity analysis?",
        timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        model: "FraudGuard Security Engine",
        status: 'completed'
      }
    ]);
  };

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div id="security-assistant-panel" className="w-full bg-[#020617] border border-slate-800 rounded-2xl shadow-2xl flex flex-col transition-all duration-300 h-full">
      {/* Header */}
      <div className="px-5 py-3 border-b border-slate-800 bg-[#0f172a] flex items-center justify-between shrink-0 rounded-t-2xl">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
            <ShieldAlert className="w-4 h-4" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-100">Cybersecurity Copilot</h2>
              <span className="inline-flex items-center gap-1.5 px-1.5 py-0.5 rounded text-[9px] font-medium bg-[#020617] text-slate-400 border border-slate-800">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                Ready
              </span>
            </div>
            <p className="text-[11px] text-slate-400">Project-aware incident analysis &amp; learning</p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => setAttachContext(!attachContext)}
            className={`inline-flex items-center gap-1.5 px-2.5 py-1.5 text-[11px] font-medium rounded-md border transition-all ${
              attachContext 
                ? 'bg-amber-500/10 border-amber-500/20 text-amber-400' 
                : 'bg-[#020617] border-slate-800 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>{attachContext ? 'Telemetry On' : 'Telemetry Off'}</span>
          </button>
          <button
            onClick={handleClearChat}
            disabled={generationState !== 'idle'}
            className="p-1.5 rounded-md bg-[#020617] text-slate-400 hover:text-slate-200 disabled:opacity-50 border border-slate-800 transition-colors"
            title="Reset conversation"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {attachContext && (
        <div className="px-5 py-2 bg-amber-950/20 border-b border-amber-500/10 flex items-center justify-between text-[11px] text-amber-200/80 shrink-0">
          <div className="flex items-center gap-2 truncate">
            {activeTelemetry ? (
              <>
                <ShieldCheck className="w-3.5 h-3.5 text-amber-500 shrink-0" />
                <span className="truncate">
                  <strong className="text-amber-400">Context:</strong> {String(activeTelemetry.scenario_name || activeTelemetry.scenario || activeTelemetry.event_type || 'Event')}
                  {activeTelemetry.risk_score !== undefined && activeTelemetry.risk_score !== null ? ` • Risk ${String(activeTelemetry.risk_score)}` : ''}
                </span>
              </>
            ) : (
              <>
                <AlertCircle className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="text-slate-400">No active telemetry selected. General mode active.</span>
              </>
            )}
          </div>
          <button onClick={() => { setAttachContext(false); onClearExternalContext?.(); }} className="text-slate-500 hover:text-slate-300 ml-2 p-0.5">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Messages */}
      <div className="p-5 space-y-5 overflow-y-auto flex-1 min-h-[300px] scrollbar-thin scrollbar-thumb-slate-800">
        {messages.map((msg, index) => (
          <div key={msg.id} className={`flex items-start gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            {msg.role === 'assistant' && (
              <div className="p-1.5 rounded bg-[#0f172a] border border-slate-800 text-slate-400 shrink-0 mt-1">
                <Bot className="w-4 h-4" />
              </div>
            )}

            <div className={`max-w-[85%] group flex flex-col ${msg.role === 'user' ? 'items-end' : 'items-start'}`}>
              <div className={`rounded-xl px-4 py-3 shadow-sm ${
                msg.role === 'user'
                  ? 'bg-slate-800 text-slate-100 rounded-tr-sm border border-slate-700/50'
                  : 'bg-[#0f172a] text-slate-200 rounded-tl-sm border border-slate-800/80'
              }`}>
                {msg.role === 'assistant' ? (
                  <MarkdownRenderer content={msg.content} />
                ) : (
                  <div className="whitespace-pre-wrap break-words text-[13px]">{msg.content}</div>
                )}

                {msg.status === 'streaming' && (
                  <div className="mt-2 flex items-center gap-2">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                    <span className="text-[10px] text-emerald-500/70 font-medium">Generating...</span>
                  </div>
                )}
                
                {msg.error && (
                  <div className="mt-3 p-2.5 rounded bg-rose-950/30 border border-rose-500/20 text-rose-400 text-xs flex items-start gap-2">
                    <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <span className="font-semibold text-rose-300">Generation Interrupted:</span> {msg.error}
                    </div>
                  </div>
                )}
              </div>

              {/* Message Footer */}
              <div className="mt-1.5 flex items-center gap-3 text-[10px] text-slate-500 px-1 opacity-0 group-hover:opacity-100 transition-opacity">
                <span>{msg.timestamp}</span>
                {msg.model && <span>• {msg.model}</span>}
                {msg.role === 'assistant' && msg.status === 'completed' && (
                  <button onClick={() => copyToClipboard(msg.content, msg.id)} className="flex items-center gap-1 hover:text-slate-300 transition-colors">
                    {copiedId === msg.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    {copiedId === msg.id ? 'Copied' : 'Copy'}
                  </button>
                )}
                {(msg.status === 'failed' || msg.status === 'interrupted') && (
                  <button onClick={() => handleRetry(index)} className="flex items-center gap-1 text-rose-400 hover:text-rose-300 transition-colors">
                    <RefreshCcw className="w-3 h-3" /> Retry
                  </button>
                )}
              </div>
            </div>

            {msg.role === 'user' && (
              <div className="p-1.5 rounded bg-slate-800 border border-slate-700/50 text-slate-400 shrink-0 mt-1">
                <User className="w-4 h-4" />
              </div>
            )}
          </div>
        ))}

        {generationState === 'waiting' && (
          <div className="flex items-start gap-3 justify-start">
            <div className="p-1.5 rounded bg-[#0f172a] border border-slate-800 text-slate-400 shrink-0 mt-1">
              <Bot className="w-4 h-4" />
            </div>
            <div className="bg-[#0f172a] border border-slate-800 rounded-xl rounded-tl-sm px-4 py-3 shadow-sm flex items-center gap-2">
              <RefreshCcw className="w-3.5 h-3.5 text-slate-500 animate-spin" />
              <span className="text-slate-400 text-xs">Waiting for model response...</span>
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Suggested Prompts */}
      <div className="px-5 py-2 bg-[#020617] border-t border-slate-800/80 shrink-0">
        <div className="flex flex-col gap-2">
          <div className="flex items-center gap-2 overflow-x-auto scrollbar-none">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider shrink-0 w-16">Learn:</span>
            {QUICK_PROMPTS_LEARNING.map((prompt, idx) => (
              <button key={`learn-${idx}`} onClick={() => handleSendMessage(prompt)} disabled={generationState !== 'idle'} className="shrink-0 px-2 py-1 rounded-md bg-[#0f172a] hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 text-[10px] transition-colors disabled:opacity-50">
                {prompt}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-2 overflow-x-auto scrollbar-none">
            <span className="text-[10px] font-semibold text-slate-500 uppercase tracking-wider shrink-0 w-16 flex items-center gap-1"><Sparkles className="w-3 h-3 text-emerald-500"/> Investigate:</span>
            {QUICK_PROMPTS_PROJECT.map((prompt, idx) => (
              <button key={`proj-${idx}`} onClick={() => { setAttachContext(true); handleSendMessage(prompt); }} disabled={generationState !== 'idle'} className="shrink-0 px-2 py-1 rounded-md bg-[#0f172a] hover:bg-slate-800 text-slate-400 hover:text-slate-200 border border-slate-800 text-[10px] transition-colors disabled:opacity-50">
                {prompt}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Composer */}
      <div className="p-4 bg-[#0f172a] border-t border-slate-800 rounded-b-2xl shrink-0">
        <div className="flex items-end gap-2">
          <div className="relative flex-1 bg-[#020617] border border-slate-700/60 rounded-xl overflow-hidden focus-within:border-emerald-500/50 focus-within:ring-1 focus-within:ring-emerald-500/50 transition-all">
            <textarea
              ref={inputRef}
              value={inputValue}
              onChange={(e) => setInputValue(e.target.value)}
              onKeyDown={handleKeyDown}
              disabled={generationState !== 'idle'}
              rows={Math.min(Math.max(inputValue.split('\n').length, 1), 5)}
              placeholder={attachContext ? "Ask about the active security telemetry..." : "Ask a cybersecurity question..."}
              className="w-full bg-transparent px-4 py-3 text-[13px] text-slate-200 placeholder-slate-500 focus:outline-none resize-none disabled:opacity-50 scrollbar-thin scrollbar-thumb-slate-700"
              style={{ minHeight: '44px', maxHeight: '120px' }}
            />
          </div>

          {generationState === 'idle' ? (
            <button
              onClick={() => handleSendMessage()}
              disabled={!inputValue.trim()}
              className="h-11 px-4 rounded-xl bg-emerald-600 hover:bg-emerald-500 text-white font-medium text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-1.5 shrink-0"
            >
              <Send className="w-4 h-4" />
              <span className="hidden sm:inline">Send</span>
            </button>
          ) : (
            <button
              onClick={handleStopGeneration}
              className="h-11 px-4 rounded-xl bg-slate-800 hover:bg-rose-500/20 hover:text-rose-400 hover:border-rose-500/30 text-slate-300 border border-slate-700 font-medium text-xs transition-all flex items-center justify-center gap-1.5 shrink-0"
            >
              <Square className="w-3.5 h-3.5 fill-current" />
              <span className="hidden sm:inline">Stop</span>
            </button>
          )}
        </div>
        <div className="mt-2 flex items-center justify-between text-[10px] text-slate-500 px-1">
          <span>Shift + Enter for newline</span>
          <span className="flex items-center gap-1">
            <CheckCircle2 className="w-3 h-3 text-emerald-500" />
            Zero Data Fabrication Enforced
          </span>
        </div>
      </div>
    </div>
  );
};

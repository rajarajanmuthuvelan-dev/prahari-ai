import { useState, useRef, useCallback, useEffect } from 'react';
import { lookupIOC } from './data/ioc-db';
import { Case, CaseListItem, EvidenceCoverage, IOC, RiskLevel, Verdict, AuthStatus } from './types';
import { DEMO_CASE, DEMO_CASES_LIST } from './data/demo-case';
import { downloadJSON, printPDF } from './lib/report-gen';
import { api } from './lib/api-client';
import { iocEvidenceCategory } from './lib/ioc-presentation';
import {
  AI_INTERPRETATION,
  formatInvestigationExplanation,
  RISK_FLOW,
} from './lib/risk-presentation';

// ─── Theme ────────────────────────────────────────────────────────────────────

type ThemeChoice = 'light' | 'dark' | 'system';

function useTheme(): [ThemeChoice, (t: ThemeChoice) => void] {
  const [theme, setThemeState] = useState<ThemeChoice>(() => {
    return (localStorage.getItem('prahari-theme') as ThemeChoice) || 'system';
  });

  const setTheme = useCallback((t: ThemeChoice) => {
    setThemeState(t);
    localStorage.setItem('prahari-theme', t);
    const dark = t === 'dark' || (t === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
  }, []);

  // Sync when system preference changes (only relevant while theme === 'system')
  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)');
    const handler = () => {
      if (theme === 'system') {
        document.documentElement.classList.toggle('dark', mq.matches);
      }
    };
    mq.addEventListener('change', handler);
    return () => mq.removeEventListener('change', handler);
  }, [theme]);

  return [theme, setTheme];
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function riskBadge(level: string | undefined) {
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-600 text-white',
    HIGH:     'bg-orange-500 text-white',
    MEDIUM:   'bg-amber-500 text-white',
    LOW:      'bg-emerald-500 text-white',
    CLEAN:    'bg-emerald-500 text-white',
    UNKNOWN:  'bg-slate-400 text-white',
    MALICIOUS:'bg-red-600 text-white',
    SUSPICIOUS:'bg-orange-500 text-white',
  };
  return map[level || 'UNKNOWN'] || 'bg-slate-400 text-white';
}

function riskText(level: string | undefined): string {
  const map: Record<string, string> = {
    CRITICAL: 'text-red-600', HIGH: 'text-orange-600',
    MEDIUM: 'text-amber-600', LOW: 'text-emerald-600', CLEAN: 'text-emerald-600',
  };
  return map[level || ''] || 'text-slate-500';
}

function riskBg(level: string | undefined): string {
  const map: Record<string, string> = {
    CRITICAL: 'bg-red-50 border-red-200', HIGH: 'bg-orange-50 border-orange-200',
    MEDIUM: 'bg-amber-50 border-amber-200', LOW: 'bg-emerald-50 border-emerald-200',
    CLEAN: 'bg-emerald-50 border-emerald-200',
    MALICIOUS: 'bg-red-50 border-red-200',
    SUSPICIOUS: 'bg-orange-50 border-orange-200',
  };
  return map[level || ''] || 'bg-slate-50 border-slate-200';
}

function verdictBadge(v: Verdict | string | undefined): string {
  if (v === 'MALICIOUS') return 'bg-red-600 text-white';
  if (v === 'SUSPICIOUS') return 'bg-orange-500 text-white';
  if (v === 'INVESTIGATING') return 'bg-amber-500 text-white';
  if (v === 'LIKELY_CLEAN') return 'bg-emerald-100 text-emerald-800 border border-emerald-300';
  if (v === 'CLEAN') return 'bg-emerald-500 text-white';
  return 'bg-slate-200 text-slate-700';
}

function authChip(status: AuthStatus) {
  const cfg: Record<string, string> = {
    PASS: 'bg-emerald-100 text-emerald-800 border-emerald-300',
    FAIL: 'bg-red-100 text-red-800 border-red-300',
    NEUTRAL: 'bg-amber-100 text-amber-800 border-amber-300',
    NONE: 'bg-slate-100 text-slate-600 border-slate-300',
    NOT_AVAILABLE: 'bg-slate-100 text-slate-400 border-slate-200',
  };
  return (
    <span className={`inline-block font-mono text-xs font-bold px-2.5 py-1 rounded border ${cfg[status] || cfg.NOT_AVAILABLE}`}>
      {status}
    </span>
  );
}

function fmt(ts: string): string {
  try { return new Date(ts).toLocaleString('en-IN', { hour12: false, timeZone: 'UTC' }) + ' UTC'; }
  catch { return ts; }
}

function fmtShort(ts: string): string {
  try { return new Date(ts).toLocaleDateString('en-IN', { day: '2-digit', month: 'short', year: 'numeric' }); }
  catch { return ts; }
}

function ScoreRing({ score, color }: { score: number; color: string }) {
  const r = 46, circ = 2 * Math.PI * r;
  const offset = circ * (1 - score / 100);
  return (
    <svg width="120" height="120" viewBox="0 0 120 120">
      <circle cx="60" cy="60" r={r} fill="none" stroke="#e2e8f0" strokeWidth="9" />
      <circle cx="60" cy="60" r={r} fill="none" stroke={color} strokeWidth="9"
        strokeLinecap="round" strokeDasharray={circ}
        strokeDashoffset={offset} transform="rotate(-90 60 60)"
        style={{ transition: 'stroke-dashoffset 1.2s ease' }} />
      <text x="60" y="56" textAnchor="middle" fill={color} fontSize="22" fontWeight="700"
        fontFamily="'JetBrains Mono', monospace">{score}</text>
      <text x="60" y="72" textAnchor="middle" fill="#94a3b8" fontSize="10"
        fontFamily="Inter, sans-serif">/ 100</text>
    </svg>
  );
}

function ScoreBar({ label, score, max, signals, color }: { label: string; score: number; max: number; signals: string[]; color: string }) {
  const pct = Math.round((score / max) * 100);
  return (
    <div>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-sm font-medium text-slate-700">{label}</span>
        <span className="font-mono text-sm font-semibold text-slate-900">
          {score} <span className="text-slate-300 font-normal">/ {max}</span>
        </span>
      </div>
      <div className="h-2.5 bg-slate-100 rounded-full overflow-hidden mb-1.5">
        <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${pct}%`, background: color }} />
      </div>
      <ul className="space-y-0.5">
        {signals.slice(0, 3).map((s, i) => (
          <li key={i} className="text-xs text-slate-500 flex items-start gap-1.5">
            <span className="text-slate-300 mt-0.5 shrink-0">›</span>{s}
          </li>
        ))}
      </ul>
    </div>
  );
}

function Kv({ k, v, mono }: { k: string; v: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex gap-3">
      <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide w-28 shrink-0 pt-0.5">{k}</span>
      <span className={`text-xs break-all ${mono ? 'font-mono text-slate-700' : 'text-slate-600'}`}>{v}</span>
    </div>
  );
}

function Tag({ label, variant = 'default' }: { label: string; variant?: 'danger' | 'warn' | 'default' }) {
  const c = variant === 'danger' ? 'bg-red-50 text-red-700 border-red-200'
    : variant === 'warn' ? 'bg-orange-50 text-orange-700 border-orange-200'
    : 'bg-slate-100 text-slate-600 border-slate-200';
  return <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${c}`}>{label}</span>;
}

function SectionCard({ title, children, className }: { title?: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={`bg-white rounded-xl border border-slate-200 ${className || ''}`}>
      {title && <div className="px-5 py-3 border-b border-slate-100 text-xs font-bold text-slate-500 uppercase tracking-widest">{title}</div>}
      <div className="p-5">{children}</div>
    </div>
  );
}

function EvidenceCoveragePanel({ coverage }: { coverage?: EvidenceCoverage }) {
  if (!coverage) {
    return (
      <SectionCard title="Evidence Coverage">
        <div className="text-sm text-slate-500">Evidence coverage details are unavailable for this case.</div>
      </SectionCard>
    );
  }
  const badgeClass = (status: string) =>
    status === 'AVAILABLE' ? 'bg-emerald-50 text-emerald-700'
      : status === 'PARTIAL' ? 'bg-amber-50 text-amber-700'
        : status === 'NOT_APPLICABLE' ? 'bg-slate-100 text-slate-500'
          : 'bg-red-50 text-red-700';
  return (
    <SectionCard title="Evidence Coverage">
      <div className="space-y-3">
        <div className="flex items-baseline justify-between gap-3">
          <span className="text-xl font-bold font-mono text-slate-800">{coverage.percentage.toFixed(0)}%</span>
          <span className="text-xs text-slate-500 text-right">
            {coverage.availableCount} available · {coverage.partialCount} partial · {coverage.unavailableCount} unavailable
            {' '}of {coverage.applicableCount} applicable
          </span>
        </div>
        <p className="text-[11px] text-slate-500">
          Partial categories count as half. This measures investigation evidence availability, not email risk.
        </p>
        {(coverage.unavailable.length > 0 || coverage.partial.length > 0) && (
          <div className="space-y-1 text-xs">
            {coverage.unavailable.length > 0 && (
              <div><strong className="text-slate-600">Unavailable:</strong> <span className="text-slate-500">{coverage.unavailable.join(', ')}</span></div>
            )}
            {coverage.partial.length > 0 && (
              <div><strong className="text-slate-600">Partial:</strong> <span className="text-slate-500">{coverage.partial.join(', ')}</span></div>
            )}
          </div>
        )}
        <details className="border-t border-slate-100 pt-2">
          <summary className="cursor-pointer text-xs font-semibold text-blue-600">Evidence category details</summary>
          <div className="mt-2 space-y-1.5">
            {Object.entries(coverage.categories).map(([key, category]) => (
              <div key={key} className="flex items-start justify-between gap-3 text-[11px]">
                <span className="text-slate-600">{category.label}<span className="text-slate-400"> · {category.detail}</span></span>
                <span className={`shrink-0 rounded px-1.5 py-0.5 font-bold ${badgeClass(category.status)}`}>{category.status}</span>
              </div>
            ))}
          </div>
        </details>
      </div>
    </SectionCard>
  );
}

function RiskFlowDisplay({ className = '' }: { className?: string }) {
  return (
    <div className={`text-center text-[10px] font-semibold text-slate-600 ${className}`}>
      <div className="flex flex-wrap items-center justify-center gap-x-1">
        {RISK_FLOW.slice(0, 4).map((step, index) => (
          <span key={step}>{index > 0 && <span className="pr-1 text-slate-300">+</span>}{step}</span>
        ))}
      </div>
      <div className="py-0.5 text-slate-300">↓</div>
      <div>{RISK_FLOW[4]}</div>
      <div className="py-0.5 text-slate-300">↓</div>
      <div>{RISK_FLOW[5]}</div>
    </div>
  );
}

// ─── Layout ───────────────────────────────────────────────────────────────────

type View = 'dashboard' | 'upload' | 'investigations' | 'investigation' | 'ioc-intel' | 'reports' | 'settings';

function PdfButton({ c, className, label = 'Download PDF' }: { c: Case; className: string; label?: string }) {
  const [busy, setBusy] = useState(false);
  const handle = async () => {
    if (busy) return;
    setBusy(true);
    try {
      await printPDF(c);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      window.alert(`Unable to generate the PDF report: ${detail}`);
    } finally {
      setBusy(false);
    }
  };
  return (
    <button onClick={handle} disabled={busy} className={className}>
      {busy ? 'Generating…' : label}
    </button>
  );
}

const NAV = [
  { id: 'dashboard' as View,      icon: '▦',  label: 'Dashboard' },
  { id: 'investigations' as View, icon: '🔍', label: 'Investigations' },
  { id: 'upload' as View,         icon: '⬆',  label: 'Upload Email' },
  { id: 'ioc-intel' as View,      icon: '⚡', label: 'IOC Intelligence' },
  { id: 'reports' as View,        icon: '📄', label: 'Reports' },
  { id: 'settings' as View,       icon: '⚙',  label: 'API Settings' },
];

function ThemeSwitcher({ theme, setTheme }: { theme: ThemeChoice; setTheme: (t: ThemeChoice) => void }) {
  const opts: { value: ThemeChoice; icon: string; label: string }[] = [
    { value: 'light',  icon: '☀', label: 'Light'  },
    { value: 'dark',   icon: '🌙', label: 'Dark'   },
    { value: 'system', icon: '🖥', label: 'System' },
  ];
  return (
    <div className="px-3 py-3 border-t border-slate-800">
      <div className="text-[10px] font-bold text-slate-600 uppercase tracking-widest mb-2">Theme</div>
      <div className="flex gap-1">
        {opts.map(o => (
          <button key={o.value} onClick={() => setTheme(o.value)}
            title={o.label}
            className={`flex-1 flex flex-col items-center gap-0.5 py-1.5 rounded-lg text-[10px] font-semibold transition-colors ${
              theme === o.value
                ? 'bg-blue-600 text-white'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'
            }`}>
            <span className="text-sm leading-none">{o.icon}</span>
            <span>{o.label}</span>
          </button>
        ))}
      </div>
    </div>
  );
}

function Sidebar({ view, setView, theme, setTheme }: {
  view: View; setView: (v: View) => void;
  theme: ThemeChoice; setTheme: (t: ThemeChoice) => void;
}) {
  return (
    <aside className="w-56 bg-slate-950 flex flex-col shrink-0 h-full border-r border-slate-900">
      <div className="px-5 py-5 border-b border-slate-800">
        <div className="text-blue-400 text-[10px] font-mono font-bold tracking-widest uppercase mb-1.5">PRAHARI AI</div>
        <div className="text-white font-semibold text-sm leading-snug">Email Threat Detection</div>
        <div className="text-slate-500 text-xs mt-0.5">& Forensic Intelligence</div>
      </div>
      <nav className="flex-1 py-4 px-2 space-y-0.5">
        {NAV.map(item => (
          <button key={item.id} onClick={() => setView(item.id)}
            className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors text-left ${
              view === item.id || (view === 'investigation' && item.id === 'investigations')
                ? 'bg-blue-600 text-white font-medium'
                : 'text-slate-400 hover:text-white hover:bg-slate-800'
            }`}>
            <span className="w-4 text-center text-sm leading-none">{item.icon}</span>
            {item.label}
          </button>
        ))}
      </nav>
      <ThemeSwitcher theme={theme} setTheme={setTheme} />
      <div className="px-4 py-3 border-t border-slate-800">
        <div className="text-slate-600 text-xs font-mono">Forensic Intelligence Platform</div>
        <div className="text-slate-700 text-xs">2026 · Prototype v1.0</div>
      </div>
    </aside>
  );
}

function PageHeader({ title, subtitle, pill, actions }: {
  title: string; subtitle?: string; pill?: string; actions?: React.ReactNode
}) {
  return (
    <div className="bg-white border-b border-slate-200 px-6 py-4 flex items-center justify-between shrink-0">
      <div className="flex items-center gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-slate-900 font-semibold text-lg leading-tight">{title}</h1>
            {pill && <span className="text-xs font-semibold bg-blue-100 text-blue-700 px-2 py-0.5 rounded-full">{pill}</span>}
          </div>
          {subtitle && <p className="text-slate-400 text-sm mt-0.5">{subtitle}</p>}
        </div>
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </div>
  );
}

// ─── Dashboard ────────────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color, icon }: {
  label: string; value: string | number; sub?: string; color?: string; icon: string;
}) {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5 flex items-start gap-4">
      <div className="text-2xl mt-0.5">{icon}</div>
      <div className="flex-1 min-w-0">
        <div className="text-xs font-semibold text-slate-400 uppercase tracking-wide">{label}</div>
        <div className={`text-3xl font-bold mt-1 font-mono ${color || 'text-slate-900'}`}>{value}</div>
        {sub && <div className="text-xs text-slate-400 mt-0.5">{sub}</div>}
      </div>
    </div>
  );
}

function Dashboard({ cases, allItems, setView, setCurrentCase }: {
  cases: Case[];
  allItems: CaseListItem[];
  setView: (v: View) => void;
  setCurrentCase: (c: Case) => void;
}) {
  const totalIOCs = cases.reduce((acc, c) => acc + c.iocs.length, 0) + 14;
  const highRisk = cases.filter(c => c.severity === 'HIGH' || c.severity === 'CRITICAL').length + 1;
  const totalAnalyzed = cases.length + DEMO_CASES_LIST.length;
  const active = allItems.filter(i => i.status !== 'Closed').length;

  return (
    <div className="flex-1 overflow-y-auto bg-slate-50">
      <div className="p-6 space-y-6">

        {/* Demo alert */}
        <div className="bg-gradient-to-r from-blue-600 to-blue-700 rounded-2xl p-5 flex items-center justify-between shadow-sm">
          <div>
            <div className="text-white font-bold text-base mb-0.5">Load Demo Investigation →</div>
            <div className="text-blue-200 text-sm">Case PRH-2026-001: PayPal phishing campaign — complete end-to-end forensic workflow</div>
          </div>
          <button onClick={() => { setCurrentCase(DEMO_CASE); setView('investigation'); }}
            className="bg-white text-blue-700 hover:bg-blue-50 font-bold text-sm px-6 py-2.5 rounded-xl transition-colors shrink-0 shadow">
            Load Demo Investigation
          </button>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-4 gap-4">
          <StatCard icon="📧" label="Emails Analyzed" value={totalAnalyzed} sub="Total in system" />
          <StatCard icon="🔴" label="High-Risk Cases" value={highRisk} sub="Require investigation" color="text-red-600" />
          <StatCard icon="⚡" label="IOCs Extracted" value={totalIOCs} sub="Across all cases" color="text-orange-600" />
          <StatCard icon="🔍" label="Active Investigations" value={active} sub="Awaiting resolution" color="text-blue-600" />
        </div>

        {(() => {
          const latest = allItems.find(item => item.id !== DEMO_CASE.id);
          return latest ? (
            <div className="bg-white rounded-xl border border-slate-200 px-5 py-4 flex items-center justify-between gap-4">
              <div className="min-w-0">
                <div className="text-xs font-bold text-slate-400 uppercase tracking-widest">Latest Threat Type</div>
                <div className="mt-1 text-lg font-semibold text-slate-800">
                  {latest.threatType || 'Suspicious Email'}
                </div>
                <div className="mt-1 text-xs text-slate-500">
                  CASE ID <span className="font-mono text-blue-700">{latest.id}</span>
                  {' · '}{latest.subject}
                </div>
                <div className="mt-1 text-[10px] text-slate-400">
                  Investigative classification based on available evidence; not a certainty.
                </div>
              </div>
              <div className="shrink-0 text-right">
                <div className="text-[10px] font-bold text-slate-400 uppercase">Risk Score</div>
                <div className="font-mono text-lg font-bold text-slate-700">{latest.riskScore} / 100</div>
              </div>
            </div>
          ) : null;
        })()}

        {/* Recent investigations */}
        <div className="bg-white rounded-xl border border-slate-200">
          <div className="px-5 py-4 border-b border-slate-100 flex items-center justify-between">
            <h2 className="font-semibold text-slate-900">Recent Investigations</h2>
            <button onClick={() => setView('upload')} className="text-sm bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-1.5 rounded-lg transition-colors">
              + Upload Email
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-100 bg-slate-50">
                  {['CASE ID', 'Subject', 'Risk Score', 'Verdict', 'IOCs', 'Status', 'Timestamp'].map(h => (
                    <th key={h} className="text-left text-[11px] font-semibold text-slate-400 uppercase tracking-wide px-5 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {allItems.slice(0, 8).map((item) => {
                  const liveCase = cases.find(c => c.id === item.id);
                  const demoCase = item.id === DEMO_CASE.id ? DEMO_CASE : null;
                  const clickable = liveCase || demoCase;
                  return (
                    <tr key={item.id}
                      onClick={() => { if (liveCase) { setCurrentCase(liveCase); setView('investigation'); } else if (demoCase) { setCurrentCase(demoCase); setView('investigation'); } }}
                      className={`border-b border-slate-50 transition-colors ${clickable ? 'hover:bg-blue-50 cursor-pointer' : 'opacity-60'}`}>
                      <td className="px-5 py-3 font-mono text-xs text-blue-700 font-semibold">{item.id}</td>
                      <td className="px-5 py-3 text-slate-700 max-w-xs truncate text-xs">{item.subject}</td>
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-14 bg-slate-100 rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${item.riskScore >= 70 ? 'bg-red-500' : item.riskScore >= 50 ? 'bg-orange-500' : item.riskScore >= 30 ? 'bg-amber-400' : 'bg-emerald-500'}`}
                              style={{ width: `${item.riskScore}%` }} />
                          </div>
                          <span className={`text-xs font-mono font-bold ${item.riskScore >= 70 ? 'text-red-600' : item.riskScore >= 50 ? 'text-orange-600' : 'text-slate-600'}`}>
                            {item.riskScore}/100
                          </span>
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <span className={`text-xs font-bold px-2 py-0.5 rounded ${verdictBadge(item.verdict)}`}>{item.verdict}</span>
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-slate-500">{item.iocCount}</td>
                      <td className="px-5 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${
                          item.status === 'Investigating' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                          item.status === 'Open' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                          'bg-slate-50 text-slate-500 border-slate-200'
                        }`}>{item.status}</span>
                      </td>
                      <td className="px-5 py-3 text-xs text-slate-400 font-mono">{fmtShort(item.timestamp)}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* PRAHARI Pipeline */}
        <PipelineStrip />

        {/* Info strip */}
        <div className="grid grid-cols-3 gap-4 text-xs text-slate-500">
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="font-semibold text-slate-700 mb-1">Scoring Method</div>
            Transparent weighted rule-based engine. Content (25) + Authentication (20) + Reputation (25) + Infrastructure (30) = 100 points.
            <div className="text-blue-600 mt-1 font-medium">Not an ML model — fully explainable.</div>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="font-semibold text-slate-700 mb-1">Threat Intelligence</div>
            Local IOC Database (offline, demo-resilient). API integrations for VirusTotal and AbuseIPDB can be configured via backend environment variables.
            <div className="text-amber-600 mt-1 font-medium">All data labeled with source.</div>
          </div>
          <div className="bg-white rounded-xl border border-slate-200 p-4">
            <div className="font-semibold text-slate-700 mb-1">GeoIP Disclaimer</div>
            Geographic data identifies <em>observed infrastructure</em> — not the attacker's physical location.
            <div className="text-slate-400 mt-1">Source: Local IOC Database / MaxMind (when configured)</div>
          </div>
        </div>

      </div>
    </div>
  );
}

// ─── Pipeline Strip ───────────────────────────────────────────────────────────

const PIPELINE_STEPS = [
  { label: 'Email Upload', icon: '📧', color: '#3b82f6' },
  { label: 'Parse Headers', icon: '⚙', color: '#6366f1' },
  { label: 'IOC Extraction', icon: '🔎', color: '#8b5cf6' },
  { label: 'Threat Intel', icon: '⚡', color: '#ec4899' },
  { label: 'Geo / Network', icon: '🌐', color: '#ef4444' },
  { label: 'Evidence Graph', icon: '🕸', color: '#f59e0b' },
  { label: 'Risk Score', icon: '📊', color: '#10b981' },
  { label: 'Forensic Report', icon: '📄', color: '#0ea5e9' },
];

function PipelineStrip() {
  return (
    <div className="bg-white rounded-xl border border-slate-200 p-5">
      <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-4">PRAHARI AI Investigation Pipeline</div>
      <div className="flex items-center gap-0 overflow-x-auto">
        {PIPELINE_STEPS.map((step, i) => (
          <div key={i} className="flex items-center shrink-0">
            <div className="flex flex-col items-center gap-1.5 px-2">
              <div className="w-10 h-10 rounded-full flex items-center justify-center text-lg shrink-0"
                style={{ background: step.color + '18', border: `1.5px solid ${step.color}40` }}>
                {step.icon}
              </div>
              <div className="text-[10px] font-semibold text-slate-500 text-center leading-tight w-16">{step.label}</div>
            </div>
            {i < PIPELINE_STEPS.length - 1 && (
              <div className="flex items-center">
                <div className="w-6 h-px bg-slate-200" />
                <div className="w-0 h-0" style={{ borderTop: '4px solid transparent', borderBottom: '4px solid transparent', borderLeft: '5px solid #cbd5e1' }} />
              </div>
            )}
          </div>
        ))}
      </div>
      <div className="mt-3 text-xs text-slate-400">
        One email → complete forensic case. Every step is traceable, every result is labeled.
      </div>
    </div>
  );
}

// ─── Investigations List ──────────────────────────────────────────────────────

function InvestigationsList({ cases, allItems, setCurrentCase, setView }: {
  cases: Case[];
  allItems: CaseListItem[];
  setCurrentCase: (c: Case) => void;
  setView: (v: View) => void;
}) {
  const [search, setSearch] = useState('');
  const filtered = allItems.filter(i =>
    !search || i.id.toLowerCase().includes(search.toLowerCase()) || i.subject.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="flex-1 overflow-y-auto bg-slate-50 p-6">
      <div className="mb-4 flex items-center gap-3">
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search by case ID or subject…"
          className="flex-1 bg-white border border-slate-200 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500" />
        <button onClick={() => setView('upload')}
          className="bg-blue-600 hover:bg-blue-700 text-white text-sm font-semibold px-5 py-2.5 rounded-xl transition-colors shrink-0">
          + Upload Email
        </button>
      </div>

      <div className="space-y-3">
        {filtered.map(item => {
          const liveCase = cases.find(c => c.id === item.id);
          const demoCase = item.id === DEMO_CASE.id ? DEMO_CASE : null;
          const theCase = liveCase || demoCase;
          const scoreColor = item.riskScore >= 70 ? '#dc2626' : item.riskScore >= 50 ? '#ea580c' : item.riskScore >= 30 ? '#d97706' : '#059669';

          return (
            <div key={item.id}
              onClick={() => { if (theCase) { setCurrentCase(theCase); setView('investigation'); } }}
              className={`bg-white rounded-xl border border-slate-200 p-5 flex items-center gap-5 ${theCase ? 'hover:border-blue-300 hover:shadow-sm cursor-pointer' : 'opacity-50'} transition-all`}>

              {/* Score ring (mini) */}
              <div className="shrink-0">
                <svg width="54" height="54" viewBox="0 0 54 54">
                  <circle cx="27" cy="27" r="21" fill="none" stroke="#e2e8f0" strokeWidth="4" />
                  <circle cx="27" cy="27" r="21" fill="none" stroke={scoreColor} strokeWidth="4"
                    strokeLinecap="round"
                    strokeDasharray={2 * Math.PI * 21}
                    strokeDashoffset={2 * Math.PI * 21 * (1 - item.riskScore / 100)}
                    transform="rotate(-90 27 27)" />
                  <text x="27" y="32" textAnchor="middle" fill={scoreColor} fontSize="11" fontWeight="700"
                    fontFamily="'JetBrains Mono', monospace">{item.riskScore}</text>
                </svg>
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-sm font-bold text-blue-700">{item.id}</span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ${verdictBadge(item.verdict)}`}>{item.verdict}</span>
                  <span className={`text-xs font-semibold px-1.5 py-0.5 rounded ${riskBadge(item.severity)}`}>{item.severity}</span>
                  {item.id === DEMO_CASE.id && <span className="text-xs font-semibold text-amber-700 bg-amber-100 px-2 py-0.5 rounded border border-amber-200">DEMO</span>}
                </div>
                <div className="text-slate-700 text-sm truncate">{item.subject}</div>
                <div className="text-xs text-slate-500 mt-1">
                  Threat type: <span className="font-semibold text-slate-700">{item.threatType || 'Suspicious Email'}</span>
                  {' · '}{item.iocCount} IOC{item.iocCount !== 1 ? 's' : ''} · {fmtShort(item.timestamp)}
                </div>
              </div>

              <div className="flex items-center gap-2 shrink-0">
                <span className={`text-xs px-2.5 py-1 rounded-full border font-medium ${
                  item.status === 'Investigating' ? 'bg-blue-50 text-blue-700 border-blue-200' :
                  item.status === 'Open' ? 'bg-amber-50 text-amber-700 border-amber-200' :
                  'bg-slate-50 text-slate-500 border-slate-200'
                }`}>{item.status}</span>
                {theCase && <span className="text-blue-400 text-lg">›</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ─── Upload Page ──────────────────────────────────────────────────────────────

const STEPS = [
  'Email parsed',
  'Headers extracted',
  'Content analyzed',
  'IOCs extracted',
  'Threat intelligence lookups completed',
  'Geo/network context generated',
  'Evidence correlated',
  'Risk score generated',
];

function UploadPage({ onAnalyzed, setView }: { onAnalyzed: (c: Case) => void; setView: (v: View) => void }) {
  const [state, setState] = useState<'idle' | 'drag' | 'processing' | 'done' | 'error'>('idle');
  const [file, setFile] = useState<File | null>(null);
  const [step, setStep] = useState(-1);
  const [errMsg, setErrMsg] = useState('');
  const ref = useRef<HTMLInputElement>(null);

  const analyze = useCallback(async (f: File) => {
    if (f.size > 10_000_000) { setErrMsg('File too large (max 10 MB).'); setState('error'); return; }
    setErrMsg('');
    setState('processing');
    setStep(0);
    try {
      setStep(1); await d(200);
      setStep(2);
      const theCase = await api.uploadEmail(f);
      setStep(3); await d(200);
      setStep(4); await d(200);
      setStep(5); await d(200);
      setStep(6); await d(200);
      setStep(7); await d(300);
      setState('done');
      onAnalyzed(theCase);
      setTimeout(() => setView('investigation'), 700);
    } catch (err) {
      setErrMsg(`Backend error: ${err instanceof Error ? err.message : String(err)}`);
      setState('error');
    }
  }, [onAnalyzed, setView]);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault(); setState('idle');
    const f = e.dataTransfer.files[0];
    if (f) { setFile(f); analyze(f); }
  };

  return (
    <div className="flex-1 overflow-y-auto bg-slate-50 p-6">
      <div className="max-w-xl mx-auto space-y-5">

        {/* Drop zone */}
        <div onDragOver={e => { e.preventDefault(); setState('drag'); }}
          onDragLeave={() => { if (state === 'drag') setState('idle'); }}
          onDrop={onDrop}
          onClick={() => state === 'idle' && ref.current?.click()}
          className={`rounded-2xl border-2 border-dashed p-14 text-center transition-all select-none
            ${state === 'drag' ? 'border-blue-500 bg-blue-50 scale-[1.01]' : 'border-slate-300 bg-white hover:border-blue-400 hover:bg-slate-50'}
            ${state === 'processing' || state === 'done' ? 'pointer-events-none opacity-60' : 'cursor-pointer'}`}>
          <input ref={ref} type="file" accept=".eml,.msg" className="hidden" onChange={e => { const f = e.target.files?.[0]; if (f) { setFile(f); analyze(f); } }} />
          <div className="text-5xl mb-4">📧</div>
          <div className="text-slate-900 font-bold text-xl mb-1">Upload Suspicious Email</div>
          <div className="text-slate-400 text-sm">
            Drop <span className="font-mono bg-slate-100 text-slate-600 px-1.5 py-0.5 rounded">.EML</span> file here or click to browse
          </div>
          <div className="text-slate-300 text-xs mt-2">Maximum 6 MB</div>
          {file && (
            <div className="mt-5 bg-slate-50 border border-slate-200 rounded-xl px-4 py-3 inline-flex items-center gap-3 text-sm">
              <span>📎</span>
              <span className="font-mono text-slate-700">{file.name}</span>
              <span className="text-slate-400">{(file.size / 1024).toFixed(1)} KB</span>
            </div>
          )}
        </div>

        {/* Analysis progress */}
        {(state === 'processing' || state === 'done') && (
          <div className="bg-white rounded-2xl border border-slate-200 p-6">
            <div className="font-semibold text-slate-900 mb-4 flex items-center gap-2">
              {state === 'processing' ? <span className="animate-pulse">⟳</span> : '✓'}
              {state === 'processing' ? 'Analyzing…' : 'Analysis complete'}
            </div>
            <div className="space-y-2.5">
              {STEPS.map((s, i) => (
                <div key={i} className={`flex items-center gap-3 text-sm transition-all duration-300 ${i <= step ? 'opacity-100' : 'opacity-20'}`}>
                  <span className={`text-base leading-none ${i < step ? 'text-emerald-500' : i === step ? 'text-blue-500' : 'text-slate-300'}`}>
                    {i < step ? '✓' : i === step ? '●' : '○'}
                  </span>
                  <span className={i < step ? 'text-emerald-700' : i === step ? 'text-blue-700 font-medium' : 'text-slate-400'}>{s}</span>
                </div>
              ))}
            </div>
            {state === 'done' && (
              <div className="mt-5 pt-4 border-t border-slate-100 text-emerald-700 text-sm font-semibold flex items-center gap-2">
                ✓ Navigating to investigation…
              </div>
            )}
          </div>
        )}

        {errMsg && (
          <div className="bg-red-50 border border-red-200 rounded-xl px-5 py-4 text-red-700 text-sm">{errMsg}</div>
        )}

        {/* Demo shortcut */}
        <div className="bg-amber-50 border border-amber-200 rounded-2xl px-5 py-4">
          <div className="font-semibold text-amber-900 text-sm mb-1">No EML file? Use the demo</div>
          <div className="text-amber-700 text-xs mb-3">Load a pre-built PayPal phishing investigation to explore the full PRAHARI forensic workflow immediately.</div>
          <button onClick={() => { onAnalyzed(DEMO_CASE); setView('investigation'); }}
            className="bg-amber-500 hover:bg-amber-600 text-white text-sm font-semibold px-4 py-2 rounded-lg transition-colors">
            Load Demo Investigation
          </button>
        </div>

      </div>
    </div>
  );
}

function d(ms: number) { return new Promise(r => setTimeout(r, ms)); }

// ─── Email Body Preview ───────────────────────────────────────────────────────

function EmailBodyPreview({ body, urls }: { body: string; urls: string[] }) {
  const [expanded, setExpanded] = useState(false);
  const LIMIT = 600;
  const trimmed = body.length > LIMIT && !expanded ? body.slice(0, LIMIT) + '…' : body;

  // Highlight suspicious URLs in the text
  const renderHighlighted = (text: string): React.ReactNode[] => {
    if (urls.length === 0) return [<span key={0}>{text}</span>];
    let result: React.ReactNode[] = [];
    let remaining = text;
    let key = 0;
    let changed = false;

    for (const url of urls) {
      const idx = remaining.indexOf(url);
      if (idx === -1) continue;
      changed = true;
      if (idx > 0) result.push(<span key={key++}>{remaining.slice(0, idx)}</span>);
      result.push(
        <span key={key++} className="bg-red-100 text-red-800 border border-red-200 rounded px-0.5 font-semibold break-all" title="Suspicious URL detected">
          {url}
        </span>
      );
      remaining = remaining.slice(idx + url.length);
    }
    if (remaining) result.push(<span key={key++}>{remaining}</span>);
    return changed ? result : [<span key={0}>{text}</span>];
  };

  return (
    <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between">
        <div className="text-xs font-bold text-slate-500 uppercase tracking-widest">Email Body Content</div>
        <div className="flex items-center gap-2">
          {urls.length > 0 && (
            <span className="text-xs bg-red-50 text-red-700 border border-red-200 px-2 py-0.5 rounded font-semibold">
              {urls.length} URL{urls.length !== 1 ? 's' : ''} highlighted
            </span>
          )}
          <span className="text-xs text-slate-400 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded">Sanitized — no HTML executed</span>
        </div>
      </div>
      <div className="p-5">
        <pre className="text-xs text-slate-600 font-mono leading-relaxed whitespace-pre-wrap break-all bg-slate-50 rounded-xl p-4 border border-slate-200 max-h-64 overflow-y-auto">
          {renderHighlighted(trimmed)}
        </pre>
        {body.length > LIMIT && (
          <button onClick={() => setExpanded(!expanded)}
            className="mt-2 text-xs text-blue-600 hover:text-blue-800 font-medium">
            {expanded ? 'Show less' : `Show full body (${body.length} chars)`}
          </button>
        )}
      </div>
    </div>
  );
}

// ─── Investigation Tabs ───────────────────────────────────────────────────────

type Tab = 'overview' | 'score' | 'iocs' | 'threat-intel' | 'auth' | 'geo' | 'graph' | 'mitre' | 'timeline' | 'report';

const TABS: { id: Tab; label: string }[] = [
  { id: 'overview',    label: 'Overview' },
  { id: 'score',       label: 'Risk Score' },
  { id: 'iocs',        label: 'IOC Analysis' },
  { id: 'threat-intel',label: 'Threat Intel' },
  { id: 'auth',        label: 'Authentication' },
  { id: 'geo',         label: 'Geo / Network' },
  { id: 'graph',       label: 'Evidence Graph' },
  { id: 'mitre',       label: 'MITRE ATT&CK' },
  { id: 'timeline',    label: 'Timeline' },
  { id: 'report',      label: 'Report' },
];

// ── Overview ──────────────────────────────────────────────────────────────────

function OverviewTab({ c, setTab }: { c: Case; setTab: (t: Tab) => void }) {
  return (
    <div className="grid grid-cols-3 gap-5">
      {/* Left: email + why flagged */}
      <div className="col-span-2 space-y-5">
        {c.isDemo && (
          <div className="flex items-center gap-2 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3 text-amber-800 text-sm">
            <span>⚠</span><strong>DEMO INVESTIGATION</strong> — Pre-loaded sample data for platform demonstration
          </div>
        )}

        <SectionCard title="Email Overview">
          <div className="space-y-2.5">
            <Kv k="From" v={c.email.from} mono />
            <Kv k="To" v={c.email.to} mono />
            <Kv k="Subject" v={c.email.subject} />
            <Kv k="Date" v={c.email.date} mono />
            <Kv k="Reply-To" v={c.email.replyTo || '—'} mono />
            <Kv k="Message-ID" v={c.email.messageId || '—'} mono />
            {c.email.receivedIPs.length > 0 && (
              <Kv k="Sending IP(s)" v={c.email.receivedIPs.join(', ')} mono />
            )}
          </div>
        </SectionCard>

        <SectionCard title="Why Flagged">
          <ul className="space-y-2">
            {c.whyFlagged.map((r, i) => (
              <li key={i} className="flex items-start gap-2.5 text-sm text-slate-700 pb-2 border-b border-slate-50 last:border-0 last:pb-0">
                <span className="text-orange-400 mt-0.5 shrink-0 text-xs">●</span>{r}
              </li>
            ))}
          </ul>
        </SectionCard>

        <SectionCard title="Case Summary">
          <p className="text-sm text-slate-600 leading-relaxed">{c.summary}</p>
          <div className="mt-3 rounded-lg border border-blue-100 bg-blue-50 px-3 py-2">
            <div className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Threat Type</div>
            <div className="mt-0.5 text-sm font-semibold text-slate-800">
              {c.threatType || 'Suspicious Email'}
            </div>
            <div className="mt-0.5 text-[10px] text-slate-500">
              Investigative classification based on available evidence; not a certainty.
            </div>
          </div>
          <div className="mt-4 grid grid-cols-4 gap-3 text-center">
            {[
              ['Evidence', c.evidenceCount],
              ['IOCs', c.iocs.length],
              ['MITRE', c.mitreMappings.length],
              ['Evidence Coverage', c.riskScore.evidenceCoverage
                ? `${c.riskScore.evidenceCoverage.percentage.toFixed(0)}%`
                : 'N/A'],
            ].map(([k, v]) => (
              <div key={String(k)} className="bg-slate-50 rounded-lg py-3">
                <div className="font-mono font-bold text-xl text-slate-900">{v}</div>
                <div className="text-xs text-slate-400 mt-0.5">{k}</div>
              </div>
            ))}
          </div>
        </SectionCard>
        <EvidenceCoveragePanel coverage={c.riskScore.evidenceCoverage} />

        {/* Email body preview */}
        {c.email.bodyText && (
          <EmailBodyPreview body={c.email.bodyText} urls={c.email.urls} />
        )}

        {/* Attachments */}
        {c.email.attachments.length > 0 && (
          <SectionCard title={`Attachments (${c.email.attachments.length})`}>
            <div className="space-y-3">
              {c.email.attachments.map((att, i) => (
                <div key={i} className="bg-slate-50 rounded-xl p-4 flex items-start gap-3 border border-slate-200">
                  <div className="text-2xl shrink-0">📎</div>
                  <div className="flex-1 min-w-0">
                    <div className="font-mono text-sm font-semibold text-slate-800">{att.filename}</div>
                    <div className="flex gap-4 mt-1.5 text-xs text-slate-500">
                      <span>{att.contentType}</span>
                      <span>{att.size > 1024 ? `${(att.size / 1024).toFixed(1)} KB` : `${att.size} bytes`}</span>
                    </div>
                    {att.sha256 && (
                      <div className="mt-1 font-mono text-xs text-slate-400 break-all">SHA-256: {att.sha256}</div>
                    )}
                    <div className="mt-2 text-xs text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-3 py-1.5">
                      Attachment metadata extracted. Content analysis unavailable for this file type. Attachments are not executed.
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </SectionCard>
        )}
      </div>

      {/* Right: verdict + quick actions */}
      <div className="space-y-5">
        <div className="bg-white rounded-xl border border-slate-200 p-5 text-center">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Verdict</div>
          <span className={`inline-block text-sm font-bold px-5 py-1.5 rounded-full mb-4 ${verdictBadge(c.verdict)}`}>
            {c.verdict}
          </span>
          <div className="grid grid-cols-2 gap-3 text-left">
            <div className="col-span-2 rounded-lg border border-blue-100 bg-blue-50 p-3">
              <div className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Threat Type</div>
              <div className="mt-1 text-lg font-bold text-slate-800">{c.threatType || 'Suspicious Email'}</div>
              <div className="mt-0.5 text-[10px] text-slate-500">
                Investigative classification based on available evidence; not a certainty.
              </div>
            </div>
            <div className="rounded-lg bg-slate-50 p-3">
              <div className="text-[10px] font-bold uppercase tracking-wide text-slate-400">Risk Score</div>
              <div className="mt-1 font-mono text-lg font-bold text-slate-800">{c.riskScore.total} / 100</div>
            </div>
            <div className="rounded-lg bg-slate-50 p-3">
              <div className="text-[10px] font-bold uppercase tracking-wide text-slate-400">Risk Band</div>
              <div className={`mt-1 text-lg font-bold ${riskText(c.riskScore.level)}`}>{c.riskScore.level}</div>
            </div>
            <div className="col-span-2 rounded-lg bg-slate-50 p-3">
              <div className="text-[10px] font-bold uppercase tracking-wide text-slate-400">Evidence Coverage</div>
              <div className="mt-1 font-mono text-lg font-bold text-slate-800">
                {c.riskScore.evidenceCoverage
                  ? `${c.riskScore.evidenceCoverage.percentage.toFixed(0)}%`
                  : 'Not available'}
              </div>
            </div>
          </div>
          <div className={`mt-3 text-xs rounded-lg px-3 py-2 text-left leading-relaxed ${riskBg(c.riskScore.level)} border`}>
            {formatInvestigationExplanation(c.riskScore)}
          </div>
          <RiskFlowDisplay className="mt-3" />
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">Quick Navigate</div>
          <div className="space-y-1.5">
            {([['score', 'Risk Score Breakdown'], ['iocs', `${c.iocs.length} IOCs Extracted`], ['threat-intel', 'Threat Intelligence'], ['auth', 'SPF / DKIM / DMARC'], ['geo', 'Geo & Network Context'], ['graph', 'Evidence Graph'], ['mitre', 'MITRE ATT&CK'], ['report', 'Generate Report']] as [Tab, string][]).map(([tab, label]) => (
              <button key={tab} onClick={() => setTab(tab)}
                className="w-full text-left text-sm text-blue-600 hover:text-blue-800 hover:bg-blue-50 px-3 py-1.5 rounded-lg transition-colors flex items-center justify-between">
                {label} <span className="text-slate-300">›</span>
              </button>
            ))}
          </div>
        </div>

        <div className="bg-white rounded-xl border border-slate-200 p-4">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">CASE ID</div>
          <div className="font-mono text-blue-700 font-bold text-sm">{c.id}</div>
          <div className="mt-3 text-xs font-bold text-slate-400 uppercase tracking-widest">THREAT TYPE</div>
          <div className="mt-1 text-sm font-semibold text-slate-700">{c.threatType || 'Suspicious'}</div>
          <div className="text-xs text-slate-400 mt-1">{fmt(c.analysisTimestamp)}</div>
        </div>
      </div>
    </div>
  );
}

// ── Risk Score ─────────────────────────────────────────────────────────────────

function ScoreTab({ c }: { c: Case }) {
  const scoreColor = c.riskScore.level === 'CRITICAL' || c.riskScore.level === 'HIGH' ? '#dc2626'
    : c.riskScore.level === 'MEDIUM' ? '#d97706' : '#059669';

  const barColor = (pct: number) =>
    pct >= 80 ? '#dc2626' : pct >= 60 ? '#ea580c' : pct >= 40 ? '#d97706' : '#059669';

  const components = [
    { label: 'Content Analysis', score: c.riskScore.content.score, max: 25, signals: c.riskScore.content.signals },
    { label: 'Authentication', score: c.riskScore.authentication.score, max: 20, signals: c.riskScore.authentication.signals },
    { label: 'IOC Reputation', score: c.riskScore.reputation.score, max: 25, signals: c.riskScore.reputation.signals },
    { label: 'Infrastructure', score: c.riskScore.infrastructure.score, max: 30, signals: c.riskScore.infrastructure.signals },
  ];

  return (
    <div className="grid grid-cols-3 gap-5">
      <div className="col-span-2 space-y-5">
        <SectionCard title="Multi-Signal Weighted Scoring">
          <div className="space-y-5">
            {components.map(comp => (
              <ScoreBar key={comp.label} label={comp.label} score={comp.score} max={comp.max}
                signals={comp.signals} color={barColor(Math.round((comp.score / comp.max) * 100))} />
            ))}
            <div className="pt-4 mt-2 border-t-2 border-slate-200 flex items-center justify-between">
              <span className="font-bold text-slate-800 text-base">Total</span>
              <span className="font-mono font-bold text-2xl" style={{ color: scoreColor }}>
                {c.riskScore.total} <span className="text-slate-300 font-normal text-lg">/ 100</span>
              </span>
            </div>
          </div>
        </SectionCard>

        <SectionCard title="Why This Score?">
          <div className={`${riskBg(c.riskScore.level)} border rounded-xl px-4 py-3 mb-4 text-sm font-medium ${riskText(c.riskScore.level)}`}>
            {formatInvestigationExplanation(c.riskScore)}
          </div>
          <div className="text-xs text-slate-400 leading-relaxed">
            <strong className="text-slate-600">Scoring methodology:</strong> This is a transparent weighted scoring system.
            Content uses deterministic rules and, when available, real BERT/RoBERTa inference. The remaining categories use:
            email content patterns (max 25), authentication failures (max 20), IOC reputation from Local IOC Database (max 25),
            and infrastructure characteristics (max 30). AI points scale linearly above the configured phishing threshold
            and round to whole points, so a small above-threshold signal can round to zero. Total: 100 points.
          </div>
        </SectionCard>
        {c.aiAnalysis && (
          <SectionCard title="AI Content Signal">
            <div className="space-y-3">
              {c.aiAnalysis.models
                .filter(model => /bert|roberta/i.test(model.name))
                .map(model => (
                  <div key={model.name} className="flex items-center justify-between text-xs">
                    <span className="text-slate-500">{model.name}</span>
                    <span className="font-mono font-semibold text-slate-700">
                      {model.phishingProbability === undefined
                        ? 'Not available'
                        : `${(model.phishingProbability * 100).toFixed(2)}% phishing`}
                    </span>
                  </div>
                ))}
              <div className="flex items-center justify-between text-xs">
                <span className="text-slate-500">Inference status</span>
                <span className="font-semibold text-slate-700">{c.aiAnalysis.status}</span>
              </div>
              {c.aiAnalysis.combinedAISignal && (
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Combined AI signal</span>
                  <span className="font-mono font-semibold text-slate-700">
                    {c.aiAnalysis.combinedAISignal.phishingProbability === undefined
                      ? 'Not available' : `${(c.aiAnalysis.combinedAISignal.phishingProbability * 100).toFixed(1)}% phishing`}
                  </span>
                </div>
              )}
              {c.aiAnalysis.models.map(model => (
                <div key={model.name} className="rounded-lg border border-slate-100 p-3 text-xs">
                  <div className="flex items-center justify-between gap-3">
                    <span className="font-semibold text-slate-700">{model.name}</span>
                    <span className="text-slate-500">{model.status}</span>
                  </div>
                  <div className="mt-1 break-all text-[10px] text-slate-400">{model.modelId}</div>
                  {model.predictedLabel && (
                    <div className="mt-2 text-slate-600">
                      Predicted label: <strong>{model.predictedLabel}</strong>
                      {model.predictedClass && ` (${model.predictedClass})`}
                    </div>
                  )}
                  {(model.benignProbability !== undefined || model.phishingProbability !== undefined) && (
                    <div className="mt-1 text-slate-600">
                      Benign {model.benignProbability !== undefined
                        ? `${(model.benignProbability * 100).toFixed(2)}%` : 'Not available'}
                      {' · '}
                      Phishing {model.phishingProbability !== undefined
                        ? `${(model.phishingProbability * 100).toFixed(2)}%` : 'Not available'}
                    </div>
                  )}
                  {model.labels && (
                    <div className="mt-1 text-slate-500">
                      {model.labels.map(item =>
                        `${item.label}: ${(item.probability * 100).toFixed(1)}%`,
                      ).join(' · ')}
                    </div>
                  )}
                  {model.chunks !== undefined && (
                    <div className="mt-1 text-slate-400">
                      {model.chunks} token chunk(s); {model.aggregation}
                    </div>
                  )}
                  {model.error && <div className="mt-2 break-words text-amber-700">{model.error}</div>}
                </div>
              ))}
              <div className="text-[11px] text-slate-400">
                Model-derived risk contribution: {c.aiAnalysis.riskContribution}/{c.aiAnalysis.riskWeight} content points.
                {' '}Analyzed {c.aiAnalysis.inputCharacters.toLocaleString()} characters
                {c.aiAnalysis.inputTruncated ? ' (input truncated at the configured limit).' : '.'}
              </div>
              <div className="rounded-lg bg-blue-50 px-3 py-2 text-[11px] text-blue-800">
                {AI_INTERPRETATION}
              </div>
              <RiskFlowDisplay className="rounded-lg border border-slate-100 bg-slate-50 px-3 py-2" />
            </div>
          </SectionCard>
        )}
      </div>

      <div className="space-y-5">
        <div className="bg-white rounded-xl border border-slate-200 p-5 text-center">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-2">Verdict</div>
          <div className={`text-base font-bold mb-3 ${riskText(c.riskScore.level)}`}>{c.verdict}</div>
          <div className="mb-3 rounded-lg border border-blue-100 bg-blue-50 p-3 text-left">
            <div className="text-[10px] font-bold uppercase tracking-wide text-blue-600">Threat Type</div>
            <div className="mt-1 text-sm font-bold text-slate-800">{c.threatType || 'Suspicious Email'}</div>
            <div className="mt-0.5 text-[10px] text-slate-500">
              Investigative classification based on available evidence; not a certainty.
            </div>
          </div>
          <div className="flex justify-center mb-3">
            <ScoreRing score={c.riskScore.total} color={scoreColor} />
          </div>
          <div className="space-y-2 text-left">
            <div className="flex justify-between gap-2 text-xs"><span className="text-slate-400">Risk Score</span><span className="font-mono font-bold text-slate-700">{c.riskScore.total} / 100</span></div>
            <div className="flex justify-between gap-2 text-xs"><span className="text-slate-400">Risk Band</span><span className={`font-bold ${riskText(c.riskScore.level)}`}>{c.riskScore.level}</span></div>
            <div className="flex justify-between gap-2 text-xs"><span className="text-slate-400">Evidence Coverage</span><span className="font-mono font-bold text-slate-700">{c.riskScore.evidenceCoverage ? `${c.riskScore.evidenceCoverage.percentage.toFixed(0)}%` : 'Not available'}</span></div>
          </div>
          <div className="mt-4 space-y-1.5 text-xs">
            {components.map(comp => (
              <div key={comp.label} className="flex items-center justify-between text-slate-500">
                <span>{comp.label}</span>
                <span className="font-mono font-semibold">{comp.score}/{comp.max}</span>
              </div>
            ))}
          </div>
        </div>

        <SectionCard title="Signal Categories">
          <div className="space-y-3 text-xs">
            {[
              ['Content (25pt)', 'Body language patterns, URL obfuscation, urgency indicators, subject analysis'],
              ['Authentication (20pt)', 'SPF / DKIM / DMARC results from email headers'],
              ['Reputation (25pt)', 'IOC threat scores from Local IOC Database or API'],
              ['Infrastructure (30pt)', 'Domain age, Tor/bulletproof hosting, lookalike domains, mailer type'],
            ].map(([k, v]) => (
              <div key={String(k)} className="pb-3 border-b border-slate-50 last:border-0 last:pb-0">
                <div className="font-semibold text-slate-700 mb-0.5">{k}</div>
                <div className="text-slate-400 leading-relaxed">{v}</div>
              </div>
            ))}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ── IOC Analysis ──────────────────────────────────────────────────────────────

function IOCsTab({ iocs }: { iocs: IOC[] }) {
  const [sel, setSel] = useState<IOC | null>(null);

  return (
    <div className="grid grid-cols-5 gap-5">
      <div className="col-span-3">
        <SectionCard title={`Extracted IOCs (${iocs.length})`} className="overflow-hidden">
          <div className="overflow-x-auto -m-5">
            <table className="w-full text-xs">
              <thead>
                <tr className="bg-slate-50 border-b border-slate-100">
                  {['Type', 'Indicator', 'Evidence Source', 'Reputation', 'Risk Contribution'].map(h => (
                    <th key={h} className="text-left font-semibold text-slate-400 uppercase tracking-wide text-[10px] px-4 py-2.5">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {iocs.map(ioc => (
                  <tr key={ioc.id} onClick={() => setSel(sel?.id === ioc.id ? null : ioc)}
                    className={`border-b border-slate-50 cursor-pointer transition-colors ${sel?.id === ioc.id ? 'bg-blue-50' : 'hover:bg-slate-50'}`}>
                    <td className="px-4 py-2.5">
                      <span className="font-mono font-bold text-[10px] bg-slate-100 text-slate-700 px-1.5 py-0.5 rounded">{ioc.type}</span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-slate-700 max-w-[180px] truncate" title={ioc.value}>{ioc.value}</td>
                    <td className="px-4 py-2.5 text-slate-400 max-w-[145px] truncate" title={ioc.source}>
                      {ioc.source}
                      <div className="text-[9px] text-slate-500">{iocEvidenceCategory(ioc)}</div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className={`font-bold text-[10px] px-1.5 py-0.5 rounded ${riskBadge(ioc.reputationStatus || ioc.status)}`}>
                        {ioc.reputationStatus || ioc.status}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="font-mono text-slate-600">
                        +{ioc.riskContribution ?? 0}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </SectionCard>
      </div>

      <div className="col-span-2">
        {sel ? (
          <div className="bg-white rounded-xl border border-blue-200 p-5 sticky top-0">
            <div className="flex items-start justify-between mb-4">
              <div>
                <span className="font-mono text-xs font-bold text-slate-400 uppercase bg-slate-100 px-2 py-0.5 rounded">{sel.type}</span>
                <div className="font-mono text-sm text-slate-900 mt-2 break-all leading-relaxed">{sel.value}</div>
              </div>
              <span className={`text-xs font-bold px-2 py-0.5 rounded ml-2 shrink-0 ${riskBadge(sel.reputationStatus || sel.status)}`}>
                {sel.reputationStatus || sel.status}
              </span>
            </div>

            {sel.intelligence?.reputation !== undefined && (
              <div className="mb-4">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-slate-400">Threat Reputation</span>
                  <span className="font-mono font-bold text-red-600">{sel.intelligence.reputation}%</span>
                </div>
                <div className="h-2 bg-slate-100 rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 rounded-full transition-all" style={{ width: `${sel.intelligence.reputation}%` }} />
                </div>
              </div>
            )}

            <div className="space-y-2 text-xs">
              <Kv k="Evidence Source" v={sel.source} />
              <Kv k="Evidence Category" v={iocEvidenceCategory(sel)} />
              <Kv k="Reputation" v={sel.reputationStatus || sel.status} />
              {sel.reputationStatus === 'UNKNOWN' && (
                <Kv k="Reason" v={sel.intelligence?.reason || 'No threat-intelligence result available'} />
              )}
              <Kv k="Risk Contribution" v={`+${sel.riskContribution ?? 0}`} />
              <Kv k="Lookup Source" v={sel.intelligence?.lookupSource || 'No reputation result'} />
              <Kv k="Lookup Status" v={sel.intelligence?.lookupStatus || 'UNAVAILABLE'} />
              {sel.intelligence?.geo?.source && <Kv k="Geo Source" v={sel.intelligence.geo.source} />}
              {sel.intelligence?.totalReports && <Kv k="Abuse Reports" v={sel.intelligence.totalReports.toLocaleString()} mono />}
              {sel.intelligence?.firstSeen && <Kv k="First Seen" v={sel.intelligence.firstSeen} mono />}
              {sel.intelligence?.lastSeen && <Kv k="Last Seen" v={sel.intelligence.lastSeen} mono />}
              {sel.intelligence?.geo?.country && <Kv k="Country" v={sel.intelligence.geo.country} />}
              {sel.intelligence?.geo?.city && <Kv k="City" v={sel.intelligence.geo.city} />}
              {sel.intelligence?.geo?.asn && <Kv k="ASN" v={sel.intelligence.geo.asn} mono />}
              {sel.intelligence?.geo?.asnName && <Kv k="ASN Name" v={sel.intelligence.geo.asnName} />}
              {sel.intelligence?.geo?.isp && <Kv k="ISP" v={sel.intelligence.geo.isp} />}
              {sel.intelligence?.geo?.networkType && <Kv k="Network Type" v={sel.intelligence.geo.networkType} />}
              {sel.intelligence?.whoisRegistrar && <Kv k="Registrar" v={sel.intelligence.whoisRegistrar} />}
              {sel.intelligence?.whoisCreated && <Kv k="Created" v={sel.intelligence.whoisCreated} mono />}
            </div>

            {sel.intelligence?.tags && sel.intelligence.tags.length > 0 && (
              <div className="mt-4 pt-3 border-t border-slate-100">
                <div className="text-xs text-slate-400 mb-2">Intelligence Tags</div>
                <div className="flex flex-wrap gap-1">
                  {sel.intelligence.tags.map((t, i) => (
                    <Tag key={i} label={t} variant={/malicious|phishing|tor|bulletproof|harvester/i.test(t) ? 'danger' : /suspicious|lookalike|newly/i.test(t) ? 'warn' : 'default'} />
                  ))}
                </div>
              </div>
            )}

            <div className="mt-3 pt-3 border-t border-slate-100 flex items-center gap-2">
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${
                sel.intelligence?.lookupSource?.includes('Local IOC Database') ? 'bg-blue-50 text-blue-700 border border-blue-200' :
                sel.intelligence?.source === 'DEMO' ? 'bg-amber-50 text-amber-700' : 'bg-slate-50 text-slate-500'
              }`}>
                Lookup: {sel.intelligence?.lookupSource || 'No reputation result'}
              </span>
              {sel.intelligence?.confidence && (
                <span className="text-[10px] text-slate-400">Conf: {sel.intelligence.confidence}%</span>
              )}
            </div>
          </div>
        ) : (
          <div className="bg-white rounded-xl border border-dashed border-slate-200 p-8 text-center text-slate-400 text-sm sticky top-0">
            <div className="text-3xl mb-3">🔍</div>
            Click an IOC row to view intelligence details
          </div>
        )}
      </div>
    </div>
  );
}

// ── Threat Intelligence ───────────────────────────────────────────────────────

function formatLookupTime(value?: string): string {
  if (!value) return 'Not available';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return 'Not available';
  return `${new Intl.DateTimeFormat('en-IN', {
    timeZone: 'Asia/Kolkata',
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)} IST`;
}

function ThreatIntelTab({ c }: { c: Case }) {
  const hasBackend = api.isAvailable();
  const actionableIOCs = c.iocs.filter(i => i.type !== 'HASH');

  return (
    <div className="space-y-5">
      <div className={`border rounded-xl px-5 py-3 text-sm ${hasBackend ? 'bg-green-50 border-green-200 text-green-800' : 'bg-slate-50 border-slate-200 text-slate-700'}`}>
        {hasBackend
          ? <><strong>Backend Analysis:</strong> Results are returned by the investigation API. Provider, status, and lookup time are shown for each available result.</>
          : null}
      </div>

      {actionableIOCs.length === 0 ? (
        <SectionCard>
          <div className="text-center py-8 text-slate-400">No IOCs extracted from this investigation.</div>
        </SectionCard>
      ) : (
        actionableIOCs.map(ioc => {
          const rep = ioc.intelligence;
          const reputationStatus = ioc.reputationStatus || ioc.status;
          const sourceLabel = rep?.lookupSource || 'No reputation result';
          return (
            <div key={ioc.id} className="bg-white rounded-xl border border-slate-200 overflow-hidden">
              {/* Header */}
              <div className={`px-5 py-3 flex items-center justify-between ${riskBg(reputationStatus)} border-b`}>
                <div className="flex items-center gap-3">
                  <span className="font-mono text-xs font-bold bg-white/80 text-slate-700 px-2 py-0.5 rounded">{ioc.type}</span>
                  <span className="font-mono text-sm font-semibold text-slate-900 break-all">{ioc.value}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className={`text-xs font-bold px-2 py-0.5 rounded ${riskBadge(reputationStatus)}`}>
                    Reputation: {reputationStatus}
                  </span>
                  <span className="text-xs text-slate-500 font-mono bg-white/60 px-2 py-0.5 rounded border">{sourceLabel}</span>
                </div>
              </div>

              <div className="p-5 grid grid-cols-2 gap-5">
                {/* Left: reputation + metadata */}
                <div>
                  {rep && rep.reputation !== undefined ? (
                    <div className="mb-4">
                      <div className="flex justify-between text-xs mb-1.5">
                        <span className="text-slate-500 font-semibold">Threat Reputation Score</span>
                        <span className="font-mono font-bold" style={{ color: rep.reputation >= 80 ? '#dc2626' : rep.reputation >= 50 ? '#ea580c' : '#059669' }}>{rep.reputation}%</span>
                      </div>
                      <div className="h-3 bg-slate-100 rounded-full overflow-hidden">
                        <div className="h-full rounded-full transition-all" style={{
                          width: `${rep.reputation}%`,
                          background: rep.reputation >= 80 ? '#dc2626' : rep.reputation >= 50 ? '#ea580c' : '#059669'
                        }} />
                      </div>
                    </div>
                  ) : (
                    <div className="mb-4 text-xs text-slate-400 bg-slate-50 rounded-lg px-3 py-2 italic">
                      {reputationStatus === 'UNKNOWN'
                        ? (rep?.reason || 'No threat-intelligence result available')
                        : 'No numeric reputation score was returned.'}
                    </div>
                  )}
                  <div className="space-y-1.5 text-xs">
                    <Kv k="Evidence Source" v={ioc.source} />
                    <Kv k="Evidence Category" v={iocEvidenceCategory(ioc)} />
                    <Kv k="Reputation" v={reputationStatus} />
                    <Kv k="Risk Contribution" v={`+${ioc.riskContribution ?? 0}`} mono />
                    <Kv k="Lookup Source" v={sourceLabel} />
                    <Kv k="Lookup Status" v={rep?.lookupStatus || 'UNAVAILABLE'} mono />
                    {rep?.firstSeen && <Kv k="First Seen" v={rep.firstSeen} mono />}
                    {rep?.lastSeen && <Kv k="Last Seen" v={rep.lastSeen} mono />}
                    {rep?.totalReports !== undefined && <Kv k="Abuse Reports" v={rep.totalReports.toLocaleString()} mono />}
                    {rep?.whoisRegistrar && <Kv k="Registrar" v={rep.whoisRegistrar} />}
                    {rep?.whoisCreated && <Kv k="Domain Created" v={rep.whoisCreated} mono />}
                    {rep?.whoisExpires && <Kv k="Domain Expires" v={rep.whoisExpires} mono />}
                  </div>
                </div>

                {/* Right: geo + ASN */}
                <div>
                  {rep?.geo ? (
                    <div className="mb-4 bg-slate-50 rounded-lg p-3">
                      <div className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-2">Geographic & Network Context</div>
                      <div className="space-y-1.5 text-xs">
                        <Kv k="Country" v={`${rep.geo.country}${rep.geo.countryCode ? ` (${rep.geo.countryCode})` : ''}`} />
                        {rep.geo.region && <Kv k="Region" v={rep.geo.region} />}
                        {rep.geo.city && <Kv k="City" v={rep.geo.city} />}
                        <Kv k="ASN" v={rep.geo.asn || '—'} mono />
                        <Kv k="ASN Name" v={rep.geo.asnName || '—'} />
                        <Kv k="ISP" v={rep.geo.isp || '—'} />
                        {rep.geo.networkType && <Kv k="Network" v={rep.geo.networkType} />}
                        <div className="text-slate-400 text-[10px] pt-1 border-t border-slate-200 mt-1 space-y-0.5">
                          <div>Geo source: {rep.geo.source || 'Not available'} · Provider: {rep.geo.provider || 'Not available'}</div>
                          <div>Status: {rep.geo.status || rep.geoStatus || 'Not available'} · Confidence: {rep.geo.confidence !== undefined ? `${rep.geo.confidence}%` : 'Not available'}</div>
                          <div>Checked: {formatLookupTime(rep.geo.checkedAt || rep.geo.lookupTimestamp)}</div>
                          {rep.geo.disagreements && Object.keys(rep.geo.disagreements).length > 0 && (
                            <div className="text-amber-700 pt-1">
                              Provider disagreement: {Object.entries(rep.geo.disagreements)
                                .map(([field, values]) => `${field} (${Object.entries(values).map(([provider, value]) => `${provider}: ${value}`).join(', ')})`)
                                .join('; ')}
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  ) : ioc.type === 'IP' && ioc.status !== 'PRIVATE' && (
                    <div className="mb-4 text-xs text-slate-400 bg-slate-50 rounded-lg px-3 py-2">
                      <div className="italic">GeoIP data unavailable for this indicator.</div>
                      {rep?.geoLookup && (
                        <div className="mt-1 not-italic">
                          Provider: {typeof rep.geoLookup.provider === 'string' ? rep.geoLookup.provider : 'Not available'}
                          {' · '}Status: {typeof rep.geoLookup.status === 'string' ? rep.geoLookup.status : rep.geoStatus || 'Not available'}
                          {' · '}Checked: {formatLookupTime(
                            typeof rep.geoLookup.checked_at === 'string'
                              ? rep.geoLookup.checked_at
                              : typeof rep.geoLookup.checkedAt === 'string'
                                ? rep.geoLookup.checkedAt
                                : undefined,
                          )}
                        </div>
                      )}
                    </div>
                  )}

                  {rep?.tags && rep.tags.length > 0 && (
                    <div>
                      <div className="text-xs text-slate-400 mb-2 font-semibold">Threat Labels</div>
                      <div className="flex flex-wrap gap-1">
                        {rep.tags.map((t, i) => (
                          <Tag key={i} label={t} variant={/malicious|phishing|tor|bulletproof|harvester|c2/i.test(t) ? 'danger' : /suspicious|lookalike|newly|watchlist/i.test(t) ? 'warn' : 'default'} />
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="px-5 pb-3 text-[10px] text-slate-400 font-mono border-t border-slate-50 pt-2">
                Lookup source: {sourceLabel} · Lookup status: {rep?.lookupStatus || 'UNAVAILABLE'} · Geo source: {rep?.geo?.source || 'Not available'} · Confidence: {rep?.confidence !== undefined ? `${rep.confidence}%` : 'Not available'} · Checked: {formatLookupTime(rep?.checkedAt || rep?.lookupTimestamp)}
                {rep?.providerResults && Object.entries(rep.providerResults).length > 0 && (
                  <div className="mt-1 space-y-0.5">
                    {Object.entries(rep.providerResults).map(([provider, rawResult]) => {
                      const result = rawResult as Record<string, unknown>;
                      return (
                        <div key={provider}>
                          {provider}: Status {typeof result.status === 'string' ? result.status : 'Not available'}
                          {' · '}Reputation state {typeof result.reputation_status === 'string' ? result.reputation_status : 'UNKNOWN'}
                          {' · '}Confidence {typeof result.confidence === 'number' ? `${result.confidence}%` : 'Not available'}
                          {' · '}Reputation {typeof result.reputation === 'number' ? result.reputation : 'Not available'}
                          {' · '}Checked {formatLookupTime(typeof result.checked_at === 'string' ? result.checked_at : undefined)}
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          );
        })
      )}
    </div>
  );
}

// ── Authentication ─────────────────────────────────────────────────────────────

function AuthTab({ c }: { c: Case }) {
  const [showRaw, setShowRaw] = useState(false);
  const auth = c.auth;
  const items: [string, typeof auth.spf, string | undefined][] = [
    ['SPF', auth.spf, auth.spfDetail],
    ['DKIM', auth.dkim, auth.dkimDetail],
    ['DMARC', auth.dmarc, auth.dmarcDetail],
  ];

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-3 gap-4">
        {items.map(([name, status, detail]) => (
          <div key={name} className={`bg-white rounded-xl border p-5 ${
            status === 'PASS' ? 'border-emerald-200' : status === 'FAIL' ? 'border-red-200' : 'border-slate-200'
          }`}>
            <div className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">{name}</div>
            {authChip(status)}
            {detail && <div className="text-xs text-slate-500 mt-3 leading-relaxed font-mono break-all">{detail}</div>}
          </div>
        ))}
      </div>

      <SectionCard title="Authentication Summary">
        <div className={`rounded-xl px-4 py-3 border text-sm font-medium ${riskBg(
          auth.spf === 'FAIL' && auth.dkim === 'FAIL' && auth.dmarc === 'FAIL' ? 'HIGH' :
          auth.spf === 'FAIL' || auth.dkim === 'FAIL' ? 'MEDIUM' : 'CLEAN'
        )}`}>
          {auth.summary}
        </div>
      </SectionCard>

      <div className="bg-white rounded-xl border border-slate-200 p-5">
        <div className="flex items-center justify-between mb-3">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-widest">Raw Authentication Headers</div>
          <button onClick={() => setShowRaw(!showRaw)} className="text-xs text-blue-600 hover:text-blue-800">
            {showRaw ? 'Hide' : 'Show'} raw headers
          </button>
        </div>
        {c.email.headers.filter(h => /authentication|received-spf|dkim-signature/i.test(h.name)).length === 0 ? (
          <div className="text-sm text-slate-400">No authentication headers found in supplied email.</div>
        ) : (
          <div className="space-y-2">
            {c.email.headers.filter(h => /authentication|received-spf|dkim/i.test(h.name)).map((h, i) => (
              <div key={i} className="bg-slate-50 rounded-lg p-3">
                <div className="text-xs font-bold text-blue-700 mb-1">{h.name}</div>
                <div className={`text-xs font-mono text-slate-600 leading-relaxed ${showRaw ? '' : 'line-clamp-2'} break-all`}>{h.value}</div>
              </div>
            ))}
          </div>
        )}
      </div>

      {c.email.headers.length > 0 && (
        <details className="bg-white rounded-xl border border-slate-200 p-5">
          <summary className="text-xs font-bold text-slate-400 uppercase tracking-widest cursor-pointer">
            All Email Headers ({c.email.headers.length})
          </summary>
          <div className="mt-4 space-y-1.5 max-h-80 overflow-y-auto">
            {c.email.headers.map((h, i) => (
              <div key={i} className="flex gap-3 text-xs">
                <span className="font-semibold text-slate-500 w-44 shrink-0 truncate">{h.name}:</span>
                <span className="font-mono text-slate-600 break-all">{h.value}</span>
              </div>
            ))}
          </div>
        </details>
      )}
    </div>
  );
}

// ── Geo / Network ──────────────────────────────────────────────────────────────

// Confidence badge colours
const confBadge = (c: string) =>
  c === 'HIGH' ? 'bg-emerald-100 text-emerald-700' :
  c === 'MEDIUM' ? 'bg-amber-100 text-amber-700' :
  c === 'LOW' ? 'bg-slate-100 text-slate-600' : 'bg-slate-100 text-slate-400';

// Infra type colour
const infraColor = (t: string) =>
  /Cloud|Hosting/.test(t) ? 'bg-blue-100 text-blue-700' :
  /VPN|Tor/.test(t) ? 'bg-red-100 text-red-700' :
  /Mobile/.test(t) ? 'bg-purple-100 text-purple-700' :
  /Education|Gov/.test(t) ? 'bg-cyan-100 text-cyan-700' :
  'bg-slate-100 text-slate-600';

// Static map tile via OpenStreetMap (no API key, no JS required)
function GeoMap({ lat, lon, label }: { lat: number; lon: number; label: string }) {
  const z = 6;
  const src = `https://staticmap.openstreetmap.de/staticmap.php?center=${lat},${lon}&zoom=${z}&size=600x160&maptype=mapnik&markers=${lat},${lon},red-pushpin`;
  return (
    <div className="rounded-lg overflow-hidden border border-slate-200 relative">
      <img src={src} alt="Approximate infrastructure location" className="w-full object-cover h-36" onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
      <div className="absolute bottom-0 left-0 right-0 bg-black/50 text-white text-[10px] px-2 py-1 font-mono">
        ⚠ {label} · {lat.toFixed(4)}°, {lon.toFixed(4)}° (Approximate)
      </div>
    </div>
  );
}

function GeoKV({ label, value, mono = true }: { label: string; value?: string; mono?: boolean }) {
  return (
    <div>
      <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wide mb-0.5">{label}</div>
      <div className={`text-xs text-slate-700 ${mono ? 'font-mono' : ''}`}>{value || 'Not available'}</div>
    </div>
  );
}

function geoFieldUnavailable(status?: string): string {
  if (status === 'NOT_RETURNED_BY_SOURCE') return 'Not returned by source';
  if (status === 'LOOKUP_FAILED' || status === 'ERROR' || status === 'TIMEOUT') {
    return 'Lookup failed';
  }
  return 'Not available';
}

function GeoTab({ c }: { c: Case }) {
  const ipIOCs = c.iocs.filter(i => i.type === 'IP');
  const geoIOCs = ipIOCs.filter(i => i.intelligence?.geo);
  const noGeoIOCs = ipIOCs.filter(i => !i.intelligence?.geo);

  const receivedPath = c.email.receivedPath || [];
  const hopPath = receivedPath.length
    ? [...receivedPath].reverse().flatMap(header => [
        header.fromHost,
        ...header.ips,
        header.byHost,
      ]).filter((value, index, values): value is string =>
        Boolean(value) && (index === 0 || value !== values[index - 1]),
      )
    : ipIOCs.filter(ioc => ioc.source.toLowerCase().includes('received')).map(ioc => ioc.value);

  return (
    <div className="space-y-5">
      {/* Forensic disclaimer */}
      <div className="bg-amber-50 border border-amber-200 rounded-xl px-5 py-3 text-sm text-amber-800 flex items-start gap-2">
        <span className="mt-0.5 shrink-0">⚠</span>
        <div>
          <strong>Geographic & Network Context of Observed IP Infrastructure.</strong>{' '}
          GeoIP identifies the geographic and network context associated with the observed IP infrastructure.
          It does not identify the attacker's exact physical location. Threat actors may operate infrastructure remotely.
        </div>
      </div>

      {/* Mail-hop path */}
      {hopPath.length > 1 && (
        <div className="bg-white rounded-xl border border-slate-200 p-4">
          <div className="text-xs font-bold text-slate-500 uppercase tracking-wide mb-3">Observed Mail-Server Path (Received Headers)</div>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-slate-400 font-mono bg-slate-50 px-2 py-1 rounded">Sender</span>
            {hopPath.map((ip, idx) => (
              <span key={idx} className="flex items-center gap-2">
                <span className="text-slate-300">→</span>
                <span className="font-mono text-xs bg-blue-50 text-blue-800 border border-blue-200 px-2 py-1 rounded">{ip}</span>
              </span>
            ))}
            <span className="text-slate-300">→</span>
            <span className="text-xs text-slate-400 font-mono bg-slate-50 px-2 py-1 rounded">Recipient</span>
          </div>
          <p className="text-[10px] text-slate-400 mt-2">
            "Observed infrastructure" — the first visible IP is not necessarily the attacker's origin. Relay hops and shared mail infrastructure are common.
          </p>
        </div>
      )}

      {/* No IPs at all */}
      {ipIOCs.length === 0 && (
        <SectionCard>
          <div className="py-8 text-center text-slate-400">No IP addresses extracted from this email.</div>
        </SectionCard>
      )}

      {/* Per-IP enriched cards */}
      {geoIOCs.map((ioc, idx) => {
        const geo = ioc.intelligence!.geo!;
        const g = geo as typeof geo & {
          postalCode?: string; timezone?: string; infraType?: string;
          reverseDns?: string; geoConfidence?: string; accuracyNote?: string;
          network?: string;
        };

        return (
          <div key={ioc.id} className="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
            {/* Card header */}
            <div className="bg-slate-900 text-white px-5 py-4 flex items-start justify-between">
              <div>
                <div className="text-[10px] font-bold text-slate-400 uppercase tracking-widest mb-1">
                  Observed IP #{idx + 1} · {ioc.source}
                </div>
                <div className="font-mono font-bold text-lg text-white">{ioc.value}</div>
                <div className="text-xs text-slate-400 mt-0.5">
                  Public IPv{ioc.value.includes(':') ? '6' : '4'} · Routable
                </div>
              </div>
              <div className="flex flex-col items-end gap-2">
                <span className={`text-xs font-bold px-2 py-1 rounded ${riskBadge(ioc.reputationStatus || ioc.status)}`}>
                  {ioc.reputationStatus || ioc.status}
                </span>
                <span className={`text-[10px] font-bold px-2 py-0.5 rounded ${confBadge(g.geoConfidence || 'Not available')}`}>
                  Geo Confidence: {g.geoConfidence || 'Not available'}
                </span>
                {g.infraType && g.infraType !== 'Unknown' && (
                  <span className={`text-[10px] font-semibold px-2 py-0.5 rounded ${infraColor(g.infraType)}`}>
                    {g.infraType}
                  </span>
                )}
              </div>
            </div>

            {/* Map */}
            {geo.lat !== undefined && geo.lon !== undefined && (
              <div className="p-4 border-b border-slate-100">
                <GeoMap lat={geo.lat} lon={geo.lon} label="Approximate infrastructure location" />
              </div>
            )}

            <div className="p-5 space-y-5">
              {/* Geographic Context */}
              <div>
                <div className="text-xs font-bold text-blue-600 uppercase tracking-wide mb-3 flex items-center gap-1">
                  🌍 Geographic Context
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <GeoKV label="Country" value={geo.country ? `${geo.country} (${geo.countryCode})` : undefined} />
                  <GeoKV label="Region" value={geo.region} />
                  <GeoKV label="City" value={geo.city} />
                  <GeoKV label="Postal Code" value={g.postalCode} />
                  <GeoKV label="Timezone" value={g.timezone} />
                  <GeoKV label="Coordinates" value={geo.lat !== undefined ? `${geo.lat.toFixed(4)}°, ${geo.lon!.toFixed(4)}° (${g.accuracyNote ?? 'Approximate'})` : undefined} />
                </div>
                {geo.disagreements && Object.keys(geo.disagreements).length > 0 && (
                  <div className="text-[10px] text-slate-400 mt-2">
                    Provider differences: {Object.entries(geo.disagreements).map(([field, providers]) =>
                      `${field}: ${Object.entries(providers).map(([provider, value]) => `${provider}=${value ?? 'Not available'}`).join(', ')}`,
                    ).join('; ')}
                  </div>
                )}
              </div>

              <div className="border-t border-slate-100" />

              {/* Network Context */}
              <div>
                <div className="text-xs font-bold text-purple-600 uppercase tracking-wide mb-3 flex items-center gap-1">
                  🔌 Network Context
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                  <GeoKV label="ASN" value={geo.asn} />
                  <GeoKV label="ASN Organization" value={geo.asnName} />
                  <GeoKV label="ISP" value={geo.isp} />
                  <GeoKV label="Organization" value={geo.org} />
                  <GeoKV label="Network" value={g.network || geoFieldUnavailable(geo.fieldStatus?.network)} />
                  <GeoKV label="Connection Type" value={geo.networkType || geoFieldUnavailable(geo.fieldStatus?.network_type)} />
                  <GeoKV label="Infrastructure Type" value={g.infraType || geoFieldUnavailable(geo.fieldStatus?.infrastructure_type)} />
                  <GeoKV label="Reverse DNS (PTR)" value={g.reverseDns || geoFieldUnavailable(geo.fieldStatus?.reverse_dns)} />
                  <GeoKV
                    label={`IP Domain / Hostname${geo.domainHostnameSource ? ` · ${geo.domainHostnameSource}` : ''}`}
                    value={geo.domainHostname || ioc.intelligence?.domainHostname}
                  />
                </div>
              </div>

              <div className="border-t border-slate-100" />

              {/* Intelligence Context */}
              <div>
                <div className="text-xs font-bold text-rose-600 uppercase tracking-wide mb-3 flex items-center gap-1">
                  🛡 Intelligence Context
                </div>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  <GeoKV
                    label="Reputation"
                    value={`${ioc.reputationStatus || ioc.status}${ioc.intelligence?.reputation !== undefined ? ` · ${ioc.intelligence.reputation}/100` : ''}`}
                  />
                  <GeoKV label="Reputation Lookup" value={ioc.intelligence?.lookupStatus || 'UNAVAILABLE'} />
                  <GeoKV label="Lookup Source" value={ioc.lookupSource || ioc.intelligence?.lookupSource || 'No reputation result'} mono={false} />
                  <GeoKV label="Geo Source" value={geo.source} />
                </div>
                {ioc.intelligence?.tags && ioc.intelligence.tags.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-3">
                    {ioc.intelligence.tags.map((t, i) => (
                      <Tag key={i} label={t} variant={/malicious|phishing|tor|bulletproof/i.test(t) ? 'danger' : /suspicious/i.test(t) ? 'warn' : 'default'} />
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Footer disclaimer */}
            <div className="bg-slate-50 border-t border-slate-100 px-5 py-2.5 text-[10px] text-slate-400 font-mono">
              GeoIP provides an approximate location of the observed IP infrastructure. Source: {geo.source} · Provider: {geo.provider || 'Not available'} · Status: {geo.status || 'Not available'} · Confidence: {geo.confidence !== undefined ? `${geo.confidence}%` : 'Not available'} · Checked: {formatLookupTime(geo.checkedAt || geo.lookupTimestamp)}
            </div>
          </div>
        );
      })}

      {/* Private / no-geo IPs */}
      {noGeoIOCs.length > 0 && (
        <div className="bg-white rounded-xl border border-slate-200 p-5">
          <div className="text-xs font-bold text-slate-400 uppercase tracking-wide mb-3">
            IPs Without Geographic Context
          </div>
          <div className="space-y-2">
            {noGeoIOCs.map(ioc => {
              const lookup = ioc.intelligence?.geoLookup;
              const provider = typeof lookup?.provider === 'string' ? lookup.provider : undefined;
              const lookupStatus = typeof lookup?.status === 'string'
                ? lookup.status
                : ioc.intelligence?.geoStatus;
              const checkedAt = typeof lookup?.checked_at === 'string'
                ? lookup.checked_at
                : typeof lookup?.checkedAt === 'string'
                  ? lookup.checkedAt
                  : undefined;
              const providerResults = lookup?.provider_results;
              return (
              <div key={ioc.id} className="flex items-center gap-3 text-xs">
                <span className="font-mono text-slate-700 bg-slate-50 px-2 py-1 rounded border border-slate-200">
                  {ioc.value}
                </span>
                <span className={`px-2 py-0.5 rounded text-[10px] font-semibold ${ioc.status === 'PRIVATE' ? 'bg-slate-100 text-slate-500' : 'bg-amber-50 text-amber-700'}`}>
                  {ioc.status === 'PRIVATE' ? 'Private / Reserved' : `GeoIP ${lookupStatus || 'Unavailable'}`}
                </span>
                <span className="text-slate-400 italic">
                  {ioc.status === 'PRIVATE'
                    ? 'Private/reserved IP — not publicly geolocatable.'
                    : `Geographic location unavailable${provider ? ` from ${provider}` : ''}.`}
                </span>
                <span className="text-slate-400 font-mono">
                  Checked: {formatLookupTime(checkedAt)}
                </span>
                <span className="text-slate-400 font-mono">
                  IP Domain / Hostname: {ioc.intelligence?.domainHostname || 'Not available'}
                  {ioc.intelligence?.domainHostnameSource
                    ? ` (${ioc.intelligence.domainHostnameSource})`
                    : ''}
                </span>
                {providerResults && typeof providerResults === 'object' && (
                  <span className="text-slate-400 font-mono">
                    {Object.entries(providerResults as Record<string, { status?: string }>)
                      .map(([name, result]) => `${name}: ${result.status || 'Not available'}`)
                      .join(' · ')}
                  </span>
                )}
              </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Bottom disclaimer */}
      <div className="text-[11px] text-slate-400 bg-slate-50 rounded-xl p-4 border border-slate-100">
        <strong className="text-slate-500">Forensic Note:</strong> GeoIP alone does not increase the risk score.
        Geographic context provides infrastructure context alongside IP reputation, authentication results, ASN information, and email content evidence.
        GeoIP identifies infrastructure context — not the attacker's physical location.
      </div>
    </div>
  );
}

// ── Evidence Graph ─────────────────────────────────────────────────────────────

const NODE_CFG: Record<string, { fill: string; label: string }> = {
  EMAIL:      { fill: '#2563eb', label: 'EMAIL' },
  URL:        { fill: '#d97706', label: 'URL' },
  DOMAIN:     { fill: '#7c3aed', label: 'DOM' },
  IP:         { fill: '#dc2626', label: 'IP' },
  ASN:        { fill: '#0891b2', label: 'ASN' },
  GEO:        { fill: '#059669', label: 'GEO' },
  REPUTATION: { fill: '#db2777', label: 'REP' },
  ATTACHMENT: { fill: '#475569', label: 'ATT' },
};

function GraphTab({ c }: { c: Case }) {
  const [sel, setSel] = useState<string | null>(null);
  const nodes = c.graphNodes;
  const edges = c.graphEdges;

  if (nodes.length === 0) {
    return <div className="text-center text-slate-400 py-16">No graph data available.</div>;
  }

  const nById: Record<string, typeof nodes[0]> = Object.fromEntries(nodes.map(n => [n.id, n]));
  const selNode = sel ? nById[sel] : null;
  const laneX: Record<string, number> = {
    DOMAIN: 145,
    URL: 390,
    ATTACHMENT: 390,
    EMAIL: 635,
    IP: 880,
    GEO: 1125,
    ASN: 1125,
    REPUTATION: 1125,
  };
  const laneCounts: Record<string, number> = {};
  const ipNodes = nodes.filter(node => node.type === 'IP');
  const auxiliaryRows = new Set<number>();
  let auxiliaryFallbackRow = 0;
  const graphNodes = nodes.map(node => {
    if (node.id === 'email') return { ...node, x: 635, y: 85 };
    const lane = node.type;
    const laneIndex = laneCounts[lane] || 0;
    laneCounts[lane] = laneIndex + 1;
    const inbound = edges.find(edge => edge.target === node.id);
    const relatedSource = inbound ? nById[inbound.source] : undefined;
    const relatedIndex = lane === 'GEO' && relatedSource?.type === 'IP'
      ? ipNodes.findIndex(candidate => candidate.id === relatedSource.id)
      : -1;
    let row = laneIndex;
    if (['GEO', 'ASN', 'REPUTATION'].includes(lane)) {
      row = relatedIndex >= 0 ? relatedIndex : auxiliaryFallbackRow;
      while (auxiliaryRows.has(row)) row += 1;
      auxiliaryRows.add(row);
      auxiliaryFallbackRow = Math.max(auxiliaryFallbackRow, row + 1);
    }
    return {
      ...node,
      x: laneX[node.type] ?? 635,
      y: lane === 'GEO' && relatedIndex >= 0
        ? 235 + relatedIndex * 130
        : 235 + row * 130,
    };
  });
  const graphNodeById: Record<string, typeof graphNodes[number]> = Object.fromEntries(
    graphNodes.map(node => [node.id, node]),
  );
  const canvasHeight = Math.max(480, ...graphNodes.map(node => node.y + 100));

  return (
    <div className="space-y-5">
      {/* Legend */}
      <div className="bg-white rounded-xl border border-slate-200 px-5 py-3 flex flex-wrap gap-4 text-xs">
        {Object.entries(NODE_CFG).filter(([k]) => nodes.some(n => n.type === k)).map(([type, cfg]) => (
          <div key={type} className="flex items-center gap-1.5">
            <div className="w-3 h-3 rounded-full" style={{ background: cfg.fill }} />
            <span className="text-slate-500">{type}</span>
          </div>
        ))}
        <span className="text-slate-300">·</span>
        <span className="text-slate-400 italic">Click a node to inspect</span>
      </div>

      {/* SVG Canvas */}
      <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
        <div className="px-5 py-3 border-b border-slate-100">
          <div className="font-semibold text-slate-900">Connected Evidence Graph</div>
          <div className="text-xs text-slate-400 mt-0.5">Connecting scattered indicators into one unified threat case</div>
        </div>
        <div className="overflow-x-auto" style={{ background: '#f8fafc' }}>
          <svg viewBox={`0 0 1270 ${canvasHeight}`} className="w-full" style={{ minWidth: 980, minHeight: 460 }}>
            <defs>
              <marker id="arr" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                <path d="M0,0 L0,8 L8,4 z" fill="#94a3b8" />
              </marker>
              <marker id="arr-sel" markerWidth="8" markerHeight="8" refX="6" refY="4" orient="auto">
                <path d="M0,0 L0,8 L8,4 z" fill="#2563eb" />
              </marker>
              <pattern id="grid" width="30" height="30" patternUnits="userSpaceOnUse">
                <circle cx="1" cy="1" r="1" fill="#e2e8f0" />
              </pattern>
              <filter id="shadow">
                <feDropShadow dx="0" dy="2" stdDeviation="3" floodOpacity="0.12" />
              </filter>
            </defs>
            {/* Grid background */}
            <rect x="0" y="0" width="1270" height={canvasHeight} fill="url(#grid)" />
            {/* Edges */}
            {edges.map(edge => {
              const s = graphNodeById[edge.source], t = graphNodeById[edge.target];
              if (!s || !t) return null;
              const dx = t.x - s.x, dy = t.y - s.y;
              const len = Math.sqrt(dx * dx + dy * dy) || 1;
              const sx = s.x + (dx / len) * 29, sy = s.y + (dy / len) * 29;
              const ex = t.x - (dx / len) * 34, ey = t.y - (dy / len) * 34;
              const curve = edge.source === 'email' ? 20 : 12;
              const cx = (sx + ex) / 2 - (dy / len) * curve;
              const cy = (sy + ey) / 2 + (dx / len) * curve;
              const isActive = s.id === sel || t.id === sel;
              const lx = 0.25 * sx + 0.5 * cx + 0.25 * ex;
              const ly = 0.25 * sy + 0.5 * cy + 0.25 * ey - 7;
              return (
                <g key={edge.id}>
                  <path d={`M${sx},${sy} Q${cx},${cy} ${ex},${ey}`}
                    fill="none"
                    stroke={isActive ? '#2563eb' : '#cbd5e1'}
                    strokeWidth={isActive ? 2.5 : 1.75}
                    markerEnd={isActive ? 'url(#arr-sel)' : 'url(#arr)'}
                    opacity={isActive ? 1 : 0.85} />
                  {edge.label && (
                    <text x={lx} y={ly} textAnchor="middle" fontSize="10" fill={isActive ? '#1d4ed8' : '#64748b'}
                      stroke="#f8fafc" strokeWidth="4" paintOrder="stroke"
                      fontFamily="Inter, sans-serif" fontWeight={isActive ? '700' : '500'}>{edge.label}</text>
                  )}
                </g>
              );
            })}
            {/* Nodes */}
            {graphNodes.map(node => {
              const cfg = NODE_CFG[node.type] || { fill: '#64748b', label: '?' };
              const isSelected = node.id === sel;
              const riskRingColor = node.risk === 'CRITICAL' ? '#dc2626' : node.risk === 'HIGH' ? '#ea580c' : node.risk === 'MEDIUM' ? '#d97706' : '';
              return (
                <g key={node.id} className="graph-node" onClick={() => setSel(isSelected ? null : node.id)}
                  filter={isSelected ? 'url(#shadow)' : undefined}>
                  {/* Risk ring */}
                  {riskRingColor && (
                    <circle cx={node.x} cy={node.y} r={33} fill="none"
                      stroke={riskRingColor} strokeWidth="2" opacity="0.5"
                      strokeDasharray="4 3" />
                  )}
                  {/* Selection ring */}
                  {isSelected && (
                    <circle cx={node.x} cy={node.y} r={33} fill="none"
                      stroke="#2563eb" strokeWidth="2.5" />
                  )}
                  {/* Main circle */}
                  <circle cx={node.x} cy={node.y} r={28}
                    fill={cfg.fill}
                    stroke="white" strokeWidth="2"
                    opacity={isSelected ? 1 : 0.88} />
                  {/* Icon/label */}
                  <text x={node.x} y={node.y + 5} textAnchor="middle" fill="white"
                    fontSize="10" fontWeight="800" fontFamily="'JetBrains Mono', monospace" letterSpacing="0.5">{cfg.label}</text>
                  {/* Node label below */}
                  <text x={node.x} y={node.y + 48} textAnchor="middle" fill="#1e293b"
                    fontSize="11" fontWeight="600" fontFamily="Inter, sans-serif">
                    {node.label.length > 28 ? node.label.slice(0, 26) + '…' : node.label}
                  </text>
                  <title>{`${node.type}: ${node.label}${node.detail ? ` — ${node.detail}` : ''}`}</title>
                </g>
              );
            })}
          </svg>
        </div>
      </div>

      {/* Selected node detail */}
      {selNode && (
        <div className="bg-white rounded-xl border border-blue-300 p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="w-9 h-9 rounded-full flex items-center justify-center text-white text-xs font-bold shrink-0"
              style={{ background: NODE_CFG[selNode.type]?.fill || '#64748b' }}>
              {NODE_CFG[selNode.type]?.label}
            </div>
            <div>
              <div className="font-mono text-sm font-bold text-slate-900">{selNode.label}</div>
              <div className="text-xs text-slate-400">{selNode.type}</div>
            </div>
            {selNode.risk && <span className={`ml-auto text-xs font-bold px-2 py-0.5 rounded ${riskBadge(selNode.risk)}`}>{selNode.risk}</span>}
          </div>
          {selNode.detail && <div className="text-xs font-mono text-slate-600 mb-2 break-all">{selNode.detail}</div>}
          <div className="text-xs text-slate-400">
            <span className="font-semibold">Connected to:</span>{' '}
            {edges.filter(e => e.source === selNode.id || e.target === selNode.id).map(e => {
              const otherId = e.source === selNode.id ? e.target : e.source;
              return nById[otherId]?.label || otherId;
            }).join(', ') || 'No connections'}
          </div>
        </div>
      )}
    </div>
  );
}

// ── MITRE ATT&CK ──────────────────────────────────────────────────────────────

const TACTIC_COLOR: Record<string, string> = {
  'Initial Access': 'bg-red-50 text-red-700 border-red-200',
  'Reconnaissance': 'bg-orange-50 text-orange-700 border-orange-200',
  'Defense Evasion': 'bg-purple-50 text-purple-700 border-purple-200',
  'Execution': 'bg-amber-50 text-amber-700 border-amber-200',
  'Persistence': 'bg-blue-50 text-blue-700 border-blue-200',
};

function MitreTab({ c }: { c: Case }) {
  if (c.mitreMappings.length === 0) {
    return (
      <SectionCard>
        <div className="py-10 text-center text-slate-400">No MITRE ATT&CK techniques identified for this investigation.</div>
      </SectionCard>
    );
  }
  return (
    <div className="space-y-4">
      <div className="bg-white rounded-xl border border-slate-200 px-5 py-3 text-sm text-slate-600">
        <strong>MITRE ATT&CK® Mapping</strong> — Only techniques with direct supporting evidence are mapped. No speculative or aspirational mappings.
      </div>
      {c.mitreMappings.map(m => (
        <div key={m.techniqueId} className="bg-white rounded-xl border border-slate-200 overflow-hidden">
          <div className="px-5 py-4 border-b border-slate-100 flex items-center gap-3 flex-wrap">
            <span className="font-mono font-bold text-blue-700 bg-blue-50 border border-blue-200 px-3 py-1 rounded-lg text-sm">{m.techniqueId}</span>
            <span className="font-semibold text-slate-900">{m.techniqueName}</span>
            <span className={`text-xs font-semibold px-2 py-0.5 rounded border ${TACTIC_COLOR[m.tactic] || 'bg-slate-50 text-slate-600 border-slate-200'}`}>{m.tactic}</span>
            <span className="text-xs font-mono text-slate-400 ml-auto">{m.tacticId}</span>
          </div>
          <div className="p-5">
            <p className="text-sm text-slate-600 leading-relaxed mb-4">{m.description}</p>
            <div className="bg-slate-50 rounded-xl px-4 py-3">
              <div className="text-xs font-bold text-slate-400 uppercase tracking-wide mb-2">Supporting Evidence</div>
              <ul className="space-y-1.5">
                {m.evidence.map((e, i) => (
                  <li key={i} className="text-xs text-slate-700 flex items-start gap-2">
                    <span className="text-blue-400 mt-0.5 shrink-0">▸</span>{e}
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── Timeline ───────────────────────────────────────────────────────────────────

function TimelineTab({ c }: { c: Case }) {
  const icon = (t: string) => ({ critical: '🔴', warning: '🟠', success: '🟢', info: '🔵' }[t] || '⚪');
  return (
    <SectionCard title={`Investigation Timeline — ${c.timeline.length} Events`}>
      <div className="relative">
        {c.timeline.map((ev, i) => (
          <div key={ev.id} className="flex gap-4 pb-6 relative">
            {i < c.timeline.length - 1 && (
              <div className="absolute left-3.5 top-8 bottom-0 w-0.5 bg-slate-100" />
            )}
            <div className="text-lg shrink-0 mt-0.5 w-7 text-center">{icon(ev.type)}</div>
            <div className="flex-1 min-w-0">
              <div className="flex items-start justify-between gap-2">
                <div className="font-semibold text-slate-900 text-sm">{ev.event}</div>
                <div className="font-mono text-[10px] text-slate-400 shrink-0 bg-slate-50 px-2 py-0.5 rounded border">{fmt(ev.timestamp)}</div>
              </div>
              <div className="text-xs text-slate-500 mt-1 leading-relaxed">{ev.detail}</div>
              {ev.isDemo && (
                <span className="inline-block mt-1 text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-1.5 py-0.5 rounded">DEMO DATA</span>
              )}
            </div>
          </div>
        ))}
      </div>
    </SectionCard>
  );
}

// ── Report ─────────────────────────────────────────────────────────────────────

function ReportTab({ c }: { c: Case }) {
  return (
    <div className="space-y-5">
      <SectionCard title="Generate Forensic Investigation Report">
        <p className="text-sm text-slate-500 mb-6 leading-relaxed">
          Export a complete forensic report for CASE ID <span className="font-mono font-bold text-blue-700">{c.id}</span>.
          {c.isDemo && <span className="text-amber-600"> Demo investigation — report will include DEMO DATA labels.</span>}
        </p>
        <div className="grid grid-cols-2 gap-4">
          <div className="border border-slate-200 rounded-2xl p-6 hover:border-blue-300 transition-colors">
            <div className="text-3xl mb-3">📄</div>
            <div className="font-bold text-slate-900 mb-1">PDF Report</div>
            <div className="text-xs text-slate-500 mb-4 leading-relaxed">
              Full formatted forensic report with email summary, multi-signal risk breakdown, IOC table, MITRE mapping, geo context, and investigation timeline. Downloads as PDF directly.
            </div>
            <PdfButton c={c} label="Download PDF Report" className="w-full bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white text-sm font-bold py-3 rounded-xl transition-colors" />
          </div>
          <div className="border border-slate-200 rounded-2xl p-6 hover:border-slate-400 transition-colors">
            <div className="text-3xl mb-3">🗂</div>
            <div className="font-bold text-slate-900 mb-1">JSON Export</div>
            <div className="text-xs text-slate-500 mb-4 leading-relaxed">
              Machine-readable structured case data. Suitable for SIEM ingestion, case management integration, or further programmatic analysis.
            </div>
            <button onClick={() => api.isAvailable() ? window.open(api.reportJsonUrl(c.id), '_blank') : downloadJSON(c)}
              className="w-full bg-slate-800 hover:bg-slate-900 text-white text-sm font-bold py-3 rounded-xl transition-colors">
              Export JSON Report
            </button>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Report Contents">
        <div className="grid grid-cols-2 gap-x-8 gap-y-1.5">
          {[
            `Case metadata (${c.id})`,
            'Email header summary',
            'SPF / DKIM / DMARC results',
            `${c.iocs.length} extracted IOC${c.iocs.length !== 1 ? 's' : ''} with details`,
            'Threat intelligence (Local IOC Database)',
            'Geo/network context per IP',
            'Multi-signal risk score breakdown',
            ...(c.aiAnalysis ? ['BERT / RoBERTa model predictions and probabilities'] : []),
            `${c.mitreMappings.length} MITRE ATT&CK technique${c.mitreMappings.length !== 1 ? 's' : ''}`,
            `${c.timeline.length}-event investigation timeline`,
            'Evidence correlation summary',
            'Why-flagged explanation list',
            'Analyst disclaimer',
          ].map((item, i) => (
            <div key={i} className="flex items-center gap-2 text-xs text-slate-600">
              <span className="text-emerald-500">✓</span>{item}
            </div>
          ))}
        </div>
      </SectionCard>

      <div className="bg-slate-50 border border-slate-200 rounded-xl px-5 py-3 text-xs text-slate-500 leading-relaxed">
        <strong className="text-slate-700">Disclaimer:</strong> This is a <em>Forensic Investigation Report</em> generated by PRAHARI AI for analytical and investigative purposes only. It does not constitute legal evidence, court-admissible certification, or a legally binding determination. All risk assessments are probabilistic estimates based on the available evidence. Reports should be reviewed by qualified security personnel before being acted upon.
      </div>
    </div>
  );
}

// ─── Investigation View ───────────────────────────────────────────────────────

function InvestigationView({ c, setView }: { c: Case; setView: (v: View) => void }) {
  const [tab, setTab] = useState<Tab>('overview');
  const scoreColor = c.riskScore.level === 'CRITICAL' || c.riskScore.level === 'HIGH' ? '#dc2626'
    : c.riskScore.level === 'MEDIUM' ? '#d97706' : '#059669';

  return (
    <>
      {/* Case header bar */}
      <div className="bg-white border-b border-slate-200 px-6 pt-4 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <button onClick={() => setView('investigations')}
              className="text-slate-400 hover:text-slate-600 text-sm flex items-center gap-1">
              ← Investigations
            </button>
            <span className="text-slate-200">|</span>
            <span className="font-mono text-blue-700 font-bold text-sm">{c.id}</span>
            <span className={`text-xs font-bold px-2.5 py-0.5 rounded ${verdictBadge(c.verdict)}`}>{c.verdict}</span>
            <span className={`text-xs font-bold px-2 py-0.5 rounded ${riskBadge(c.severity)}`}>{c.severity} RISK</span>
            {c.isDemo && <span className="text-xs font-semibold text-amber-700 bg-amber-100 border border-amber-300 px-2 py-0.5 rounded">DEMO</span>}
          </div>
          <div className="flex items-center gap-4">
            <div className="text-right">
              <div className="font-mono font-bold text-xl" style={{ color: scoreColor }}>
                {c.riskScore.total}<span className="text-slate-300 text-base font-normal">/100</span>
              </div>
              <div className="text-xs text-slate-400 -mt-0.5">Risk Score</div>
            </div>
            <PdfButton c={c} label="PDF" className="text-xs bg-blue-600 hover:bg-blue-700 disabled:opacity-60 text-white font-semibold px-3 py-1.5 rounded-lg transition-colors" />
            <button onClick={() => api.isAvailable() ? window.open(api.reportJsonUrl(c.id), '_blank') : downloadJSON(c)}
              className="text-xs border border-slate-200 hover:bg-slate-50 text-slate-600 font-semibold px-3 py-1.5 rounded-lg transition-colors">JSON</button>
          </div>
        </div>
        <div className="text-sm text-slate-500 mb-3 truncate">{c.email.subject}</div>

        {/* Tabs */}
        <div className="flex overflow-x-auto gap-0 -mb-px">
          {TABS.map(t => (
            <button key={t.id} onClick={() => setTab(t.id)}
              className={`px-4 py-2 text-sm font-medium whitespace-nowrap transition-all border-b-2 ${
                tab === t.id
                  ? 'border-blue-600 text-blue-700 bg-blue-50/60'
                  : 'border-transparent text-slate-500 hover:text-slate-700 hover:bg-slate-50'
              }`}>
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto bg-slate-50 p-6">
        {tab === 'overview'     && <OverviewTab c={c} setTab={setTab} />}
        {tab === 'score'        && <ScoreTab c={c} />}
        {tab === 'iocs'         && <IOCsTab iocs={c.iocs} />}
        {tab === 'threat-intel' && <ThreatIntelTab c={c} />}
        {tab === 'auth'         && <AuthTab c={c} />}
        {tab === 'geo'          && <GeoTab c={c} />}
        {tab === 'graph'        && <GraphTab c={c} />}
        {tab === 'mitre'        && <MitreTab c={c} />}
        {tab === 'timeline'     && <TimelineTab c={c} />}
        {tab === 'report'       && <ReportTab c={c} />}
      </div>
    </>
  );
}

// ─── IOC Intelligence Page ───────────────────────────────────────────────────

function IOCIntelPage() {
  const [query, setQuery] = useState('');
  const [result, setResult] = useState<ReturnType<typeof lookupIOC> | 'not-found' | null>(null);

  const search = () => {
    if (!query.trim()) return;
    const r = lookupIOC(query.trim());
    setResult(r || 'not-found');
  };

  const EXAMPLES = ['185.220.101.47', 'paypa1-notifications.com', '194.165.16.11', 'microsofft-login.com'];

  return (
    <div className="flex-1 overflow-y-auto bg-slate-50 p-6">
      <div className="max-w-2xl mx-auto space-y-6">
        <SectionCard title="IOC Lookup — Local Database">
          <div className="flex gap-2 mb-3">
            <input value={query} onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && search()}
              placeholder="IP address, domain, or URL…"
              className="flex-1 border border-slate-200 rounded-xl px-4 py-2.5 text-sm font-mono focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
            <button onClick={search}
              className="bg-blue-600 hover:bg-blue-700 text-white px-5 py-2.5 rounded-xl text-sm font-bold transition-colors">
              Look Up
            </button>
          </div>
          <div className="flex flex-wrap gap-2">
            {EXAMPLES.map(ex => (
              <button key={ex} onClick={() => { setQuery(ex); const r = lookupIOC(ex); setResult(r || 'not-found'); }}
                className="text-xs font-mono text-blue-600 hover:text-blue-800 bg-blue-50 hover:bg-blue-100 px-2.5 py-1 rounded-lg border border-blue-200 transition-colors">
                {ex}
              </button>
            ))}
          </div>
        </SectionCard>

        {result === 'not-found' && (
          <div className="bg-white rounded-xl border border-slate-200 p-6 text-center text-slate-400">
            <div className="text-2xl mb-2">🔍</div>
            <div className="font-semibold text-slate-600">Not found in Local IOC Database</div>
            <div className="text-xs mt-1">Configure VirusTotal / AbuseIPDB API keys in backend .env for external lookup.</div>
          </div>
        )}

        {result && result !== 'not-found' && (
          <div className="bg-white rounded-xl border border-slate-200 overflow-hidden">
            <div className={`px-5 py-3 border-b flex items-center justify-between ${
              result.reputation >= 80 ? 'bg-red-50 border-red-200' : result.reputation >= 50 ? 'bg-orange-50 border-orange-200' : 'bg-amber-50 border-amber-200'
            }`}>
              <div>
                <span className="font-mono text-xs font-bold bg-white/80 text-slate-700 px-2 py-0.5 rounded mr-2">{result.type}</span>
                <span className="font-mono font-bold text-slate-900 text-sm">{result.value}</span>
              </div>
              <span className={`text-xs font-bold px-2 py-0.5 rounded ${result.reputation >= 80 ? 'bg-red-600 text-white' : 'bg-orange-500 text-white'}`}>
                {result.reputation}% threat
              </span>
            </div>
            <div className="p-5 grid grid-cols-2 gap-4 text-xs">
              {result.country && <Kv k="Country" v={result.country} />}
              {result.region && <Kv k="Region" v={result.region} />}
              {result.city && <Kv k="City" v={result.city} />}
              {result.asn && <Kv k="ASN" v={result.asn} mono />}
              {result.asnName && <Kv k="ASN Name" v={result.asnName} />}
              {result.isp && <Kv k="ISP" v={result.isp} />}
              {result.networkType && <Kv k="Network Type" v={result.networkType} />}
              {result.totalReports && <Kv k="Abuse Reports" v={result.totalReports.toLocaleString()} mono />}
              {result.firstSeen && <Kv k="First Seen" v={result.firstSeen} mono />}
              {result.whoisRegistrar && <Kv k="Registrar" v={result.whoisRegistrar} />}
              {result.whoisCreated && <Kv k="Domain Created" v={result.whoisCreated} mono />}
            </div>
            <div className="px-5 pb-4">
              <div className="flex flex-wrap gap-1">
                {result.tags.map((t, i) => <Tag key={i} label={t} variant={/malicious|phishing|tor|bulletproof/i.test(t) ? 'danger' : 'warn'} />)}
              </div>
            </div>
            <div className="px-5 pb-3 text-[10px] text-slate-400 font-mono border-t border-slate-100 pt-2">Source: LOCAL_DB</div>
          </div>
        )}

        <SectionCard title={`Local IOC Database — ${10} Records`}>
          <div className="text-xs text-slate-400 mb-3">
            10 pre-loaded IOC records for demo resilience. Real deployments connect to VirusTotal, AbuseIPDB, and MaxMind GeoIP via backend API.
          </div>
          <div className="space-y-1.5">
            {['185.220.101.47', '194.165.16.11', '91.108.4.40', '45.142.212.100', '23.106.122.234',
              'paypa1-notifications.com', 'paypa1-verify-account.net', 'secure-paypa1-verify.net',
              'microsofft-login.com', 'invoice-secure-portal.net'].map(ioc => {
              const r = lookupIOC(ioc);
              return (
                <div key={ioc} className="flex items-center justify-between text-xs py-1.5 border-b border-slate-50 last:border-0">
                  <button onClick={() => { setQuery(ioc); setResult(r || 'not-found'); }}
                    className="font-mono text-blue-600 hover:text-blue-800 text-left">{ioc}</button>
                  {r && <span className={`font-bold px-1.5 py-0.5 rounded text-[10px] ${r.reputation >= 80 ? 'bg-red-100 text-red-700' : 'bg-amber-100 text-amber-700'}`}>{r.reputation}%</span>}
                </div>
              );
            })}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

// ─── Reports Page ─────────────────────────────────────────────────────────────

function ReportsPage({ cases, setCurrentCase, setView }: {
  cases: Case[];
  setCurrentCase: (c: Case) => void;
  setView: (v: View) => void;
}) {
  const all = [DEMO_CASE, ...cases.filter(c => c.id !== DEMO_CASE.id)];
  const scoreColor = (s: number) => s >= 70 ? '#dc2626' : s >= 50 ? '#ea580c' : s >= 30 ? '#d97706' : '#059669';

  return (
    <div className="flex-1 overflow-y-auto bg-slate-50 p-6">
      <div className="space-y-3">
        {all.map(c => (
          <div key={c.id} className="bg-white rounded-xl border border-slate-200 p-5 flex items-center gap-5">
            <div className="shrink-0">
              <svg width="52" height="52" viewBox="0 0 52 52">
                <circle cx="26" cy="26" r="20" fill="none" stroke="#e2e8f0" strokeWidth="4" />
                <circle cx="26" cy="26" r="20" fill="none" stroke={scoreColor(c.riskScore.total)} strokeWidth="4"
                  strokeLinecap="round" strokeDasharray={2 * Math.PI * 20}
                  strokeDashoffset={2 * Math.PI * 20 * (1 - c.riskScore.total / 100)}
                  transform="rotate(-90 26 26)" />
                <text x="26" y="31" textAnchor="middle" fill={scoreColor(c.riskScore.total)} fontSize="11"
                  fontWeight="700" fontFamily="'JetBrains Mono', monospace">{c.riskScore.total}</text>
              </svg>
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-mono text-sm font-bold text-blue-700">{c.id}</span>
                <span className={`text-xs font-bold px-2 py-0.5 rounded ${verdictBadge(c.verdict)}`}>{c.verdict}</span>
                <span className="text-xs font-semibold text-blue-700">{c.threatType || 'Suspicious Email'}</span>
                {c.isDemo && <span className="text-xs font-semibold text-amber-700 bg-amber-100 px-2 py-0.5 rounded border border-amber-200">DEMO</span>}
              </div>
              <div className="text-sm text-slate-600 truncate">{c.email.subject}</div>
              <div className="text-xs text-slate-400 font-mono mt-1">{fmt(c.analysisTimestamp)}</div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button onClick={() => { setCurrentCase(c); setView('investigation'); }}
                className="text-sm bg-slate-800 hover:bg-slate-900 text-white px-3 py-1.5 rounded-lg transition-colors font-semibold">View</button>
              <PdfButton c={c} label="PDF" className="text-sm border border-slate-200 hover:bg-slate-50 disabled:opacity-60 text-slate-600 px-3 py-1.5 rounded-lg transition-colors font-semibold" />
              <button onClick={() => api.isAvailable() ? window.open(api.reportJsonUrl(c.id), '_blank') : downloadJSON(c)} className="text-sm border border-slate-200 hover:bg-slate-50 text-slate-600 px-3 py-1.5 rounded-lg transition-colors font-semibold">JSON</button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Settings / API Status Page ───────────────────────────────────────────────

function SettingsPage() {
  const backendUrl = (import.meta.env.VITE_API_URL as string) || '';
  const hasBackend = api.isAvailable();
  const [theme, setTheme] = useTheme();

  const [status, setStatus] = useState<Record<string, boolean | null>>({
    virustotal: null, abuseipdb: null, geoip: null, backend: null,
  });
  const [checking, setChecking] = useState(false);

  const checkStatus = async () => {
    setChecking(true);
    if (hasBackend) {
      try {
        const r = await fetch(`${backendUrl}/api/status`, { signal: AbortSignal.timeout(5000) });
        if (r.ok) {
          const d = await r.json();
          setStatus({ virustotal: d.virustotal, abuseipdb: d.abuseipdb, geoip: d.geoip, backend: true });
        } else {
          setStatus(s => ({ ...s, backend: false }));
        }
      } catch {
        setStatus(s => ({ ...s, backend: false }));
      }
    } else {
      setStatus({ virustotal: false, abuseipdb: false, geoip: false, backend: false });
    }
    setChecking(false);
  };

  const badge = (val: boolean | null, label: string) => {
    if (val === null) return <span className="text-xs bg-slate-100 text-slate-500 font-semibold px-2 py-0.5 rounded">Not checked</span>;
    if (val) return <span className="text-xs bg-green-100 text-green-700 font-bold px-2 py-0.5 rounded">Configured</span>;
    return <span className="text-xs bg-red-100 text-red-600 font-bold px-2 py-0.5 rounded">Not Configured</span>;
  };

  const integrations = [
    { key: 'backend', name: 'FastAPI Backend', desc: 'Required for server-side analysis. Uses the same-origin API proxy unless VITE_API_URL is configured.', icon: '🖥' },
    { key: 'virustotal', name: 'VirusTotal', desc: 'IP and domain reputation. Configure VIRUSTOTAL_API_KEY in the backend environment.', icon: '🛡' },
    { key: 'abuseipdb', name: 'AbuseIPDB', desc: 'IP abuse confidence scoring. Configure ABUSEIPDB_API_KEY in the backend environment.', icon: '⚠' },
    { key: 'geoip', name: 'MaxMind GeoIP', desc: 'Uses MaxMind when configured and IP-API as a network fallback. City-level location is approximate.', icon: '🌐' },
  ];

  const themeOpts: { value: ThemeChoice; icon: string; label: string; desc: string }[] = [
    { value: 'light',  icon: '☀',  label: 'Light',  desc: 'Always use the light interface.' },
    { value: 'dark',   icon: '🌙', label: 'Dark',   desc: 'Professional SOC dark interface.' },
    { value: 'system', icon: '🖥', label: 'System', desc: 'Follow OS/browser preference.' },
  ];

  return (
    <div className="p-8 max-w-3xl">
      <div className="mb-8">
        <div className="text-xs font-mono font-bold tracking-widest text-slate-400 uppercase mb-2">Configuration</div>
        <h1 className="text-2xl font-bold text-slate-900">Settings</h1>
        <p className="text-slate-500 text-sm mt-1">Application preferences and threat intelligence integrations.</p>
      </div>

      {/* Theme */}
      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden mb-6">
        <div className="px-6 py-4 border-b border-slate-100">
          <div className="font-semibold text-slate-900 text-sm">Application Theme</div>
          <p className="text-xs text-slate-400 mt-0.5">Your preference is saved and applied on next load.</p>
        </div>
        <div className="px-6 py-5 flex gap-3">
          {themeOpts.map(o => (
            <button key={o.value} onClick={() => setTheme(o.value)}
              className={`flex-1 flex flex-col items-center gap-2 py-4 rounded-xl border-2 transition-all ${
                theme === o.value
                  ? 'border-blue-600 bg-blue-50 text-blue-700'
                  : 'border-slate-200 hover:border-slate-300 text-slate-600 hover:bg-slate-50'
              }`}>
              <span className="text-2xl leading-none">{o.icon}</span>
              <span className="text-sm font-semibold">{o.label}</span>
              <span className="text-[10px] text-center text-slate-400 leading-tight px-2">{o.desc}</span>
              {theme === o.value && <span className="text-[10px] font-bold text-blue-600">● Active</span>}
            </button>
          ))}
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-2xl overflow-hidden mb-6">
        <div className="px-6 py-4 border-b border-slate-100 flex items-center justify-between">
          <div className="font-semibold text-slate-900 text-sm">Integration Status</div>
          <button onClick={checkStatus} disabled={checking}
            className="text-xs bg-blue-600 hover:bg-blue-700 text-white font-semibold px-4 py-1.5 rounded-lg transition-colors disabled:opacity-50">
            {checking ? 'Checking…' : 'Check Status'}
          </button>
        </div>
        <div className="divide-y divide-slate-100">
          {integrations.map(({ key, name, desc, icon }) => (
            <div key={key} className="px-6 py-4 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3">
                <div className="text-xl w-8 text-center">{icon}</div>
                <div>
                  <div className="font-semibold text-slate-900 text-sm">{name}</div>
                  <div className="text-xs text-slate-500 mt-0.5">{desc}</div>
                </div>
              </div>
              <div className="shrink-0">{badge(status[key], name)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-white border border-slate-200 rounded-2xl p-6 mb-6">
        <div className="font-semibold text-slate-900 text-sm mb-3">Backend API Configuration</div>
        <div className={`text-xs font-mono px-3 py-1.5 rounded mb-3 inline-block ${hasBackend ? 'bg-green-50 text-green-700' : 'bg-amber-50 text-amber-700'}`}>
          VITE_API_URL = {backendUrl || '(same-origin API proxy)'}
        </div>
        <p className="text-sm text-slate-600 leading-relaxed">
          When no backend is configured, PRAHARI uses <strong>live GeoIP lookups</strong> (ipwho.is/ip-api.com, no key required) for all public IPs, and the <strong>local IOC database</strong> as a reputation fallback for the 10 pre-loaded known-malicious indicators. Threat intelligence from VirusTotal and AbuseIPDB requires the backend.
        </p>
      </div>

      <div className="bg-white border border-slate-200 rounded-2xl p-6">
        <div className="font-semibold text-slate-900 text-sm mb-3">Intelligence Source Priority</div>
        <div className="space-y-2">
          {[
            { n: 1, label: 'Live API', desc: 'VirusTotal, AbuseIPDB, MaxMind GeoIP (requires backend + keys)', color: 'blue' },
            { n: 2, label: 'Cached Result', desc: 'Redis cache (1h TTL) — fast repeat lookups', color: 'indigo' },
            { n: 3, label: 'Live GeoIP', desc: 'ipwho.is / ip-api.com — free, no key, browser-side', color: 'cyan' },
            { n: 4, label: 'Local IOC Database', desc: '10 pre-loaded known-malicious indicators — offline fallback', color: 'amber' },
            { n: 5, label: 'No Data Available', desc: 'Shown honestly when no source returns a result', color: 'slate' },
          ].map(({ n, label, desc, color }) => (
            <div key={n} className="flex items-start gap-3">
              <div className={`w-6 h-6 rounded-full bg-${color}-100 text-${color}-700 text-xs font-bold flex items-center justify-center shrink-0 mt-0.5`}>{n}</div>
              <div>
                <span className="text-sm font-semibold text-slate-800">{label}</span>
                <span className="text-xs text-slate-500 ml-2">{desc}</span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// ─── App Root ─────────────────────────────────────────────────────────────────

export default function App() {
  const [view, setView] = useState<View>('dashboard');
  const [currentCase, setCurrentCase] = useState<Case | null>(null);
  const [cases, setCases] = useState<Case[]>([]);
  const [theme, setTheme] = useTheme();

  const allItems: CaseListItem[] = [
    ...cases.map(c => ({
      id: c.id, subject: c.email.subject, riskScore: c.riskScore.total,
      verdict: c.verdict, iocCount: c.iocs.length,
      status: 'Investigating', timestamp: c.createdAt, severity: c.severity,
      threatType: c.threatType,
    })),
    ...DEMO_CASES_LIST.filter(d => !cases.find(c => c.id === d.id)),
  ];

  const onAnalyzed = useCallback((c: Case) => {
    setCurrentCase(c);
    setCases(prev => prev.find(e => e.id === c.id) ? prev : [c, ...prev]);
  }, []);

  const navigate = (v: View) => {
    setView(v);
  };

  const PAGE_HEADER: Partial<Record<View, [string, string]>> = {
    dashboard:       ['Dashboard', 'PRAHARI AI — Email Threat Detection & Forensic Intelligence'],
    upload:          ['Upload Email', 'Analyze a suspicious .EML file'],
    investigations:  ['Investigations', `${allItems.length} case${allItems.length !== 1 ? 's' : ''} in system`],
    'ioc-intel':     ['IOC Intelligence', 'Indicator lookup and enrichment — Local IOC Database'],
    reports:         ['Reports', 'Forensic investigation reports'],
  };

  const hdr = PAGE_HEADER[view];

  return (
    <div className="flex h-full">
      <Sidebar view={view} setView={navigate} theme={theme} setTheme={setTheme} />
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {hdr && <PageHeader title={hdr[0]} subtitle={hdr[1]} />}

        {view === 'dashboard'      && <Dashboard cases={cases} allItems={allItems} setView={navigate} setCurrentCase={c => { setCurrentCase(c); }} />}
        {view === 'upload'         && <UploadPage onAnalyzed={onAnalyzed} setView={navigate} />}
        {view === 'investigations' && <InvestigationsList cases={cases} allItems={allItems} setCurrentCase={setCurrentCase} setView={navigate} />}
        {view === 'investigation'  && currentCase && <InvestigationView c={currentCase} setView={navigate} />}
        {view === 'investigation'  && !currentCase && (
          <div className="flex-1 flex items-center justify-center bg-slate-50">
            <div className="text-center">
              <div className="text-slate-400 mb-4 text-sm">No investigation selected.</div>
              <button onClick={() => { setCurrentCase(DEMO_CASE); }}
                className="bg-blue-600 text-white px-6 py-2.5 rounded-xl text-sm font-bold hover:bg-blue-700 transition-colors">
                Load Demo Investigation
              </button>
            </div>
          </div>
        )}
        {view === 'ioc-intel' && <IOCIntelPage />}
        {view === 'reports'   && <ReportsPage cases={cases} setCurrentCase={setCurrentCase} setView={navigate} />}
        {view === 'settings'  && <SettingsPage />}
      </div>
    </div>
  );
}

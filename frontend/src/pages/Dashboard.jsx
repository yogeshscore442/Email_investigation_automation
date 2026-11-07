import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Skull, Mail, Globe,
  Hash, ExternalLink, ArrowRight, RefreshCw, BarChart3, Radio,
  CheckCircle2, AlertCircle, Cpu, Zap, Activity, Info
} from 'lucide-react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import MetricCard from '../components/MetricCard';
import RiskBadge from '../components/RiskBadge';
import VerdictBadge from '../components/VerdictBadge';
import { getDashboardStats } from '../api/client';

export default function Dashboard({ onSelectInvestigation, onNewInvestigation }) {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchStats = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getDashboardStats();
      setStats(data);
    } catch (err) {
      setError('Failed to fetch SOC dashboard statistics. Ensure backend is running.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <p className="text-sm text-slate-400">Loading SOC telemetry & investigation metrics...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="max-w-4xl mx-auto p-6 bg-red-950/30 border border-red-800/40 rounded-2xl text-center mt-10">
        <AlertTriangle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-red-300">Telemetry Unavailable</h3>
        <p className="text-sm text-slate-300 mt-1">{error}</p>
        <button
          onClick={fetchStats}
          className="mt-4 px-4 py-2 bg-red-800/60 hover:bg-red-700 text-white rounded-lg text-sm font-semibold transition-colors"
        >
          Retry Connection
        </button>
      </div>
    );
  }

  const metrics = stats?.metrics || {};
  const recents = stats?.recent_investigations || [];
  const riskDist = stats?.risk_distribution || [];
  const iocs = stats?.ioc_stats || {};

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Hero Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-sky-400">
            <Radio className="w-3.5 h-3.5 animate-pulse text-sky-400" />
            <span>SOC Telemetry & DFIR Automated Analysis</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
            Automated Phishing Investigation Operations
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Real-time mailbox forensics, threat intelligence enrichment, and risk scoring engine.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchStats}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button
            onClick={onNewInvestigation}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-sm font-semibold shadow-lg shadow-sky-500/20 transition-all"
          >
            <span>Analyze New Email</span>
            <ArrowRight className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Top Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Total Investigated"
          value={metrics.total_investigated || 0}
          icon={Mail}
          color="sky"
          subtitle="Processed mail items"
        />
        <MetricCard
          title="Critical Threats"
          value={metrics.critical_risk_count || 0}
          icon={Skull}
          color="red"
          subtitle="Score >= 80 (Malware/Phish)"
        />
        <MetricCard
          title="Phishing Detected"
          value={metrics.phishing_detected || 0}
          icon={ShieldAlert}
          color="orange"
          subtitle="Confirmed malicious campaigns"
        />
        <MetricCard
          title="Suspicious Mails"
          value={metrics.suspicious_count || 0}
          icon={AlertTriangle}
          color="amber"
          subtitle="Anomalous / BEC indicators"
        />
        <MetricCard
          title="Legitimate Clean"
          value={metrics.legitimate_count || 0}
          icon={ShieldCheck}
          color="emerald"
          subtitle="SPF/DKIM/DMARC passed"
        />
      </div>

      {/* Charts & IOC Analytics */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Distribution Chart */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur">
          <div className="flex items-center justify-between pb-4 border-b border-slate-800">
            <div className="flex items-center gap-2">
              <BarChart3 className="w-5 h-5 text-sky-400" />
              <h2 className="text-base font-bold text-white">Risk Tier Distribution</h2>
            </div>
            <span className="text-xs text-slate-400">Categorized by score bounds</span>
          </div>

          <div className="h-64 mt-4 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={riskDist} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <XAxis dataKey="name" stroke="#9CA3AF" fontSize={11} tickLine={false} />
                <YAxis stroke="#9CA3AF" fontSize={11} tickLine={false} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: 'rgba(36, 36, 36, 0.5)' }}
                  contentStyle={{ backgroundColor: '#171717', borderColor: '#393939', borderRadius: '8px', color: '#E5E7EB' }}
                />
                <Bar dataKey="count" radius={[6, 6, 0, 0]}>
                  {riskDist.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* IOC Threat Intelligence Aggregation */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Hash className="w-5 h-5 text-sky-400" />
                <h2 className="text-base font-bold text-white">Extracted Threat IOCs</h2>
              </div>
              <span className="text-xs font-semibold text-sky-400">{metrics.total_iocs_extracted || 0} Total</span>
            </div>

            <div className="grid grid-cols-2 gap-3 mt-4">
              <div className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-xl">
                <p className="text-xs text-slate-400">Extracted URLs</p>
                <p className="text-2xl font-bold text-sky-400 mt-1">{iocs.urls || 0}</p>
              </div>
              <div className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-xl">
                <p className="text-xs text-slate-400">Target Domains</p>
                <p className="text-2xl font-bold text-indigo-400 mt-1">{iocs.domains || 0}</p>
              </div>
              <div className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-xl">
                <p className="text-xs text-slate-400">Observed IPs</p>
                <p className="text-2xl font-bold text-amber-400 mt-1">{iocs.ips || 0}</p>
              </div>
              <div className="p-3 bg-slate-950/50 border border-slate-800/80 rounded-xl">
                <p className="text-xs text-slate-400">Payload Hashes</p>
                <p className="text-2xl font-bold text-red-400 mt-1">{iocs.hashes || 0}</p>
              </div>
            </div>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800/80 text-xs text-slate-400">
            All IOCs are sanitized and defanged before analyst rendering to eliminate inadvertent payload detonation.
          </div>
        </div>
      </div>

      {/* Live Threat Intelligence & AI Integration Hub */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-sky-400" />
            <h2 className="text-base font-bold text-white">Threat Intelligence & AI Integrations Status</h2>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800">
            <Info className="w-3.5 h-3.5 text-sky-400" />
            <span>Anti-Fabrication Guardrail: Unavailable APIs degrade safely without simulating threat data</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
          {Object.entries(stats?.integrations || {}).map(([key, item]) => {
            const isLive = item.mode === 'live';
            const isDegraded = item.mode === 'degraded';
            return (
              <div
                key={key}
                className={`p-3.5 rounded-xl border flex flex-col justify-between transition-all ${isLive
                    ? 'bg-emerald-950/20 border-emerald-800/40'
                    : isDegraded
                      ? 'bg-amber-950/15 border-amber-800/30'
                      : 'bg-slate-950/40 border-slate-800'
                  }`}
              >
                <div>
                  <div className="flex items-center justify-between gap-1 mb-1.5">
                    <span className="text-xs font-bold text-white truncate">{item.name}</span>
                    {isLive ? (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                        <CheckCircle2 className="w-2.5 h-2.5" />
                        Live
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                        <AlertCircle className="w-2.5 h-2.5" />
                        Degraded
                      </span>
                    )}
                  </div>
                  <p className="text-[11px] text-slate-400">
                    {item.model ? `Model: ${item.model}` : item.capabilities?.[0] || 'Operational'}
                  </p>
                </div>
                <div className="mt-2.5 pt-2 border-t border-slate-800/60 text-[10px] text-slate-500">
                  {isLive ? 'Active queries enabled' : 'Deterministic fallback active'}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Recent Investigations Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl backdrop-blur">
        <div className="p-5 border-b border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-bold text-white">Recent Investigations</h2>
            <p className="text-xs text-slate-400">Select any record to inspect headers, intelligence, and IOCs</p>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 text-xs font-semibold uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Sender (From)</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Artifacts</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {recents.length === 0 ? (
                <tr>
                  <td colSpan="6" className="text-center py-8 text-slate-500 italic">
                    No investigations recorded yet. Click "Analyze New Email" to upload evidence.
                  </td>
                </tr>
              ) : (
                recents.map((inv) => (
                  <tr
                    key={inv.id}
                    onClick={() => onSelectInvestigation(inv.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-semibold text-white max-w-xs truncate">
                      {inv.subject || '[No Subject]'}
                    </td>
                    <td className="py-3.5 px-4 text-xs font-mono text-slate-300 max-w-[200px] truncate">
                      {inv.sender}
                    </td>
                    <td className="py-3.5 px-4">
                      <VerdictBadge verdict={inv.verdict} size="sm" />
                    </td>
                    <td className="py-3.5 px-4">
                      <RiskBadge score={inv.overall_risk_score} category={inv.risk_category} size="sm" />
                    </td>
                    <td className="py-3.5 px-4 text-xs text-slate-400">
                      {inv.urls_count} URLs · {inv.attachments_count} Files · {inv.rule_hits_count} Rules
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectInvestigation(inv.id);
                        }}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
                      >
                        <span>Inspect</span>
                        <ExternalLink className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


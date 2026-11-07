import React, { useState, useEffect } from 'react';
import {
  ShieldAlert, ShieldCheck, AlertTriangle, Skull, Users, Laptop,
  Activity, ArrowRight, RefreshCw, CheckCircle2, AlertCircle, XCircle,
  ExternalLink, Clock, Layers, Lock, Play, Ban, Check, X, Info, FileText,
  Search
} from 'lucide-react';
import MetricCard from '../components/MetricCard';
import RiskBadge from '../components/RiskBadge';
import {
  getIncidents, getIncidentStats, getIncident, triggerCorrelation,
  approvePlaybookAction, rejectPlaybookAction, executePlaybookAction
} from '../api/client';

export default function IncidentDashboard({ onSelectInvestigation }) {
  const [stats, setStats] = useState(null);
  const [incidents, setIncidents] = useState([]);
  const [selectedIncident, setSelectedIncident] = useState(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [correlating, setCorrelating] = useState(false);
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [actionMessage, setActionMessage] = useState(null);
  const [loadError, setLoadError] = useState(null);

  const formatNumber = (val) => {
    if (val === null || val === undefined) return '0';
    const num = Number(val);
    return isNaN(num) ? String(val) : num.toLocaleString();
  };

  const fetchTelemetry = async () => {
    try {
      setLoading(true);
      setLoadError(null);
      const [statsData, incidentsData] = await Promise.all([
        getIncidentStats(),
        getIncidents()
      ]);
      setStats(statsData);
      setIncidents(incidentsData);
      setIncidents(Array.isArray(incidentsData) ? incidentsData : []);
    } catch (err) {
      console.error('Failed to load incident telemetry:', err);
      setLoadError(err.message || 'Failed to connect to incident correlation service.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTelemetry();
  }, []);

  const handleRunCorrelation = async () => {
    try {
      setCorrelating(true);
      await triggerCorrelation();
      const res = await triggerCorrelation();
      await fetchTelemetry();
      setActionMessage({ type: 'success', text: 'SOC correlation pass executed across all investigations.' });
      setTimeout(() => setActionMessage(null), 4000);
      const count = res?.incidents_created ?? res?.total_incidents ?? 0;
      setActionMessage({
        type: 'success',
        text: `SOC correlation pass executed across all investigations (${count} incident(s) active).`
      });
      setTimeout(() => setActionMessage(null), 5000);
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Failed to run correlation engine.' });
      const errMsg = err.response?.data?.error || err.message || 'Failed to run correlation engine.';
      setActionMessage({ type: 'error', text: errMsg });
    } finally {
      setCorrelating(false);
    }
  };

  const handleOpenDetail = async (incidentId) => {
    try {
      setDetailLoading(true);
      const data = await getIncident(incidentId);
      setSelectedIncident(data);
    } catch (err) {
      console.error('Failed to load incident detail:', err);
      setActionMessage({ type: 'error', text: 'Failed to load incident detail.' });
    } finally {
      setDetailLoading(false);
    }
  };

  const handleApproveAction = async (actionId) => {
    if (!selectedIncident) return;
    try {
      await approvePlaybookAction(selectedIncident.id, actionId, 'SOC Lead Analyst');
      const updated = await getIncident(selectedIncident.id);
      setSelectedIncident(updated);
      setActionMessage({ type: 'success', text: 'Playbook action approved.' });
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Failed to approve action.' });
      setActionMessage({ type: 'error', text: err.response?.data?.error || 'Failed to approve action.' });
    }
  };

  const handleRejectAction = async (actionId) => {
    if (!selectedIncident) return;
    try {
      await rejectPlaybookAction(selectedIncident.id, actionId, 'SOC Lead Analyst', 'Rejected by analyst override.');
      const updated = await getIncident(selectedIncident.id);
      setSelectedIncident(updated);
      setActionMessage({ type: 'info', text: 'Playbook action rejected.' });
      setTimeout(() => setActionMessage(null), 3000);
    } catch (err) {
      setActionMessage({ type: 'error', text: 'Failed to reject action.' });
      setActionMessage({ type: 'error', text: err.response?.data?.error || 'Failed to reject action.' });
    }
  };

  const handleExecuteAction = async (actionId) => {
    if (!selectedIncident) return;
    if (!window.confirm('Confirm execution of this containment action? Disruptive network modifications may occur.')) return;
    try {
      const res = await executePlaybookAction(selectedIncident.id, actionId);
      const updated = await getIncident(selectedIncident.id);
      setSelectedIncident(updated);
      setActionMessage({ type: 'success', text: `Action executed: ${res.execution_result?.message || 'Success'}` });
      setTimeout(() => setActionMessage(null), 4000);
    } catch (err) {
      setActionMessage({ type: 'error', text: err.response?.data?.error || 'Failed to execute action.' });
    }
  };

  const incidentList = Array.isArray(incidents) ? incidents : [];
  const filteredIncidents = incidentList.filter(inc => {
    if (severityFilter !== 'ALL' && (inc.severity || '').toUpperCase() !== severityFilter) {
      return false;
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      const titleMatch = (inc.title || '').toLowerCase().includes(q);
      const numMatch = (inc.incident_number || '').toLowerCase().includes(q);
      const campMatch = (inc.campaign_name || '').toLowerCase().includes(q);
      return titleMatch || numMatch || campMatch;
    }
    return true;
  });

  if (loading && !stats) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <p className="text-sm text-slate-400">Loading SOC correlation telemetry & SIEM status...</p>
      </div>
    );
  }

  const siem = stats?.siem_status || {};

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-8">
      {/* Alert Notification */}
      {actionMessage && (
        <div className={`p-4 rounded-xl border flex items-center justify-between text-sm ${actionMessage.type === 'success'
          ? 'bg-emerald-950/40 border-emerald-800 text-emerald-200'
          : actionMessage.type === 'error'
            ? 'bg-red-950/40 border-red-800 text-red-200'
            : 'bg-slate-900 border-slate-700 text-slate-200'
          }`}>
          <div className="flex items-center gap-2">
            <Info className="w-4 h-4" />
            <span>{actionMessage.text}</span>
          </div>
          <button onClick={() => setActionMessage(null)} className="text-slate-400 hover:text-white">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Error Banner */}
      {loadError && (
        <div className="p-4 rounded-xl border bg-red-950/40 border-red-800 text-red-200 flex items-center justify-between text-sm">
          <div className="flex items-center gap-2">
            <AlertCircle className="w-4 h-4 text-red-400" />
            <span>{loadError}</span>
          </div>
          <button
            onClick={fetchTelemetry}
            className="px-3 py-1 bg-slate-800 hover:bg-slate-700 text-white rounded text-xs font-semibold"
          >
            Retry
          </button>
        </div>
      )}

      {/* Hero Header */}
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl">
        <div>
          <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-sky-400">
            <Layers className="w-3.5 h-3.5 text-sky-400" />
            <span>SOC Incident Correlation & SIEM Integration Hub</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold text-white mt-1">
            Correlated Incidents & Threat Campaigns
          </h1>
          <p className="text-sm text-slate-400 mt-1">
            Cross-investigation IOC correlation, Splunk & Wazuh event mapping, and analyst-authorized containment playbooks.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={fetchTelemetry}
            className="flex items-center gap-2 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-sm font-medium border border-slate-700 transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            <span>Refresh</span>
          </button>
          <button
            onClick={handleRunCorrelation}
            disabled={correlating}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-gradient-to-r from-sky-500 to-indigo-600 hover:from-sky-400 hover:to-indigo-500 text-white text-sm font-semibold shadow-lg shadow-sky-500/20 transition-all disabled:opacity-50"
          >
            <Activity className={`w-4 h-4 ${correlating ? 'animate-spin' : ''}`} />
            <span>{correlating ? 'Correlating...' : 'Run Correlation Engine'}</span>
          </button>
        </div>
      </div>

      {/* Top Incident Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        <MetricCard
          title="Total Incidents"
          value={stats?.total_incidents || 0}
          icon={Layers}
          color="sky"
          subtitle="Clustered threat campaigns"
        />
        <MetricCard
          title="Critical Incidents"
          value={stats?.critical_count || 0}
          icon={Skull}
          color="red"
          subtitle="Multi-user / malware verified"
        />
        <MetricCard
          title="High Severity"
          value={stats?.high_count || 0}
          icon={ShieldAlert}
          color="orange"
          subtitle="Confirmed phishing campaigns"
        />
        <MetricCard
          title="Targeted Identities"
          value={stats?.affected_users_count || 0}
          icon={Users}
          color="amber"
          subtitle="Distinct targeted employees"
        />
        <MetricCard
          title="Affected Workstations"
          value={stats?.affected_endpoints_count || 0}
          icon={Laptop}
          color="indigo"
          subtitle="Workstations mapped to telemetry"
        />
      </div>

      {/* SIEM Operational Telemetry Panel */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 shadow-xl backdrop-blur space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-sky-400" />
            <h2 className="text-base font-bold text-white">Enterprise SIEM & EDR Connectivity Status</h2>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-400 bg-slate-950/60 px-3 py-1.5 rounded-lg border border-slate-800">
            <Info className="w-3.5 h-3.5 text-sky-400" />
            <span>Anti-Fabrication Guardrail: Telemetry is reported as 'Unavailable' when SIEM is offline</span>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Splunk Card */}
          <div className="p-4 rounded-xl border bg-slate-950/40 border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-bold text-white">Splunk Enterprise SIEM</span>
                  {siem.splunk?.version && (
                    <span className="text-[10px] font-mono bg-sky-950 text-sky-400 px-1.5 py-0.5 rounded border border-sky-800">
                      v{siem.splunk.version}
                    </span>
                  )}
                </div>
                {siem.splunk?.mode === 'live' || siem.splunk?.status === 'operational' ? (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                    <CheckCircle2 className="w-3 h-3" /> Live Connected
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/30">
                    <AlertCircle className="w-3 h-3" /> Degraded Mode
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Capabilities: Sysmon Event ID 1/3/10/11 Process & Sockets, Windows Security 4624/4625 Authentication Correlation, PowerShell Script Block Auditing.
              </p>
              <div className="mt-3 flex flex-wrap gap-2 text-xs">
                <span className="font-mono text-slate-400 bg-slate-900 px-2 py-1 rounded border border-slate-800">
                  Host: <span className="text-slate-200">{siem.splunk?.host || '127.0.0.1:8089'}</span>
                </span>
                {siem.splunk?.indexes && Object.keys(siem.splunk.indexes).length > 0 && (
                  <div className="flex flex-wrap gap-1.5 items-center">
                    {Object.entries(siem.splunk.indexes).map(([idx, cnt]) => (
                      <span key={idx} className="font-mono text-[11px] bg-slate-800/80 text-sky-300 px-1.5 py-0.5 rounded border border-slate-700">
                        {idx}: <span className="font-semibold text-white">{cnt.toLocaleString()}</span>
                        {idx}: <span className="font-semibold text-white">{formatNumber(cnt)}</span>
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400 flex items-center justify-between">
              <span>{siem.splunk?.message || 'Ready for live SPL correlation'}</span>
              {(siem.splunk?.total_events > 0) && (
                <span className="text-emerald-400 font-semibold">{formatNumber(siem.splunk.total_events)} total events indexed</span>
              )}
            </div>
          </div>

          {/* Wazuh Card */}
          <div className="p-4 rounded-xl border bg-slate-950/40 border-slate-800 flex flex-col justify-between">
            <div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-bold text-white">Wazuh EDR & SIEM Manager</span>
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                  <Info className="w-3 h-3" /> Optional / Not Configured
                </span>
              </div>
              <p className="text-xs text-slate-400 mt-2">
                Capabilities: Real-time Endpoint Threat Alerts, Agent Inventory Telemetry, Authorized Host Network Isolation.
              </p>
              <div className="mt-3 text-xs font-mono text-slate-500 bg-slate-900 px-2 py-1 rounded border border-slate-800 inline-block">
                Status: Wazuh not installed in this lab. Operating in Splunk-only validation mode.
              </div>
            </div>
            <div className="mt-4 pt-3 border-t border-slate-800 text-[11px] text-slate-400">
              {siem.wazuh?.message || 'Wazuh EDR is optional. System is currently operating in Splunk-only live validation mode.'}
            </div>
          </div>
        </div>
      </div>

      {/* Correlated Incidents Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl backdrop-blur">
        <div className="p-5 border-b border-slate-800 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div>
            <h2 className="text-base font-bold text-white">Correlated SOC Security Incidents</h2>
            <p className="text-xs text-slate-400">Clustered by shared indicators, campaign signatures, and target scope</p>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            {/* Search Input */}
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-400" />
              <input
                type="text"
                placeholder="Search incidents or campaigns..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>

            {/* Severity Filter */}
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-slate-400">Severity:</span>
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM'].map(s => (
                <button
                  key={s}
                  onClick={() => setSeverityFilter(s)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${severityFilter === s
                    ? 'bg-sky-500 text-white'
                    : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
                    }`}
                >
                  {s}
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 text-xs font-semibold uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Incident ID</th>
                <th className="py-3 px-4">Campaign Title</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Status</th>
                <th className="py-3 px-4">Scope</th>
                <th className="py-3 px-4">Linked Emails</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredIncidents.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-10 text-slate-400">
                    <div className="flex flex-col items-center justify-center gap-2">
                      <Layers className="w-8 h-8 text-slate-600" />
                      <p className="font-semibold text-slate-300">No correlated incidents found</p>
                      <p className="text-xs text-slate-500 max-w-md">
                        {searchQuery
                          ? `No incidents matched filter '${searchQuery}'. Clear search to view all.`
                          : 'No incidents clustered yet. Upload sample emails and click "Run Correlation Engine" to group investigations into threat campaigns.'}
                      </p>
                      <button
                        onClick={handleRunCorrelation}
                        disabled={correlating}
                        className="mt-2 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded-lg text-xs font-semibold border border-slate-700 transition-colors"
                      >
                        {correlating ? 'Correlating...' : 'Run Correlation Pass'}
                      </button>
                    </div>
                  </td>
                </tr>
              ) : (
                filteredIncidents.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => handleOpenDetail(inc.id)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-sky-400 text-xs">
                      {inc.incident_number}
                    </td>
                    <td className="py-3.5 px-4 font-semibold text-white max-w-xs truncate">
                      {inc.title}
                    </td>
                    <td className="py-3.5 px-4">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-bold ${inc.severity === 'Critical'
                        ? 'bg-red-500/10 text-red-400 border border-red-500/30'
                        : inc.severity === 'High'
                          ? 'bg-orange-500/10 text-orange-400 border border-orange-500/30'
                          : 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                        }`}>
                        {inc.severity}
                      </span>
                    </td>
                    <td className="py-3.5 px-4 text-xs font-medium text-slate-300">
                      {inc.status}
                    </td>
                    <td className="py-3.5 px-4 text-xs text-slate-400">
                      {inc.affected_users_count} User(s) · {inc.affected_endpoints_count} Host(s)
                      {inc.affected_users_count || 0} User(s) · {inc.affected_endpoints_count || 0} Host(s)
                    </td>
                    <td className="py-3.5 px-4 text-xs text-slate-400">
                      {inc.investigations_count} Investigation(s)
                      {inc.investigations_count || 0} Investigation(s)
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          handleOpenDetail(inc.id);
                        }}
                        className="inline-flex items-center gap-1 text-xs font-semibold text-sky-400 hover:text-sky-300 transition-colors"
                      >
                        <span>Investigate</span>
                        <ArrowRight className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Incident Detail Modal / Drawer */}
      {selectedIncident && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-5xl w-full max-h-[90vh] overflow-y-auto shadow-2xl p-6 space-y-6">
            {/* Modal Header */}
            <div className="flex items-start justify-between pb-4 border-b border-slate-800">
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-sky-400 bg-sky-950/60 px-2.5 py-1 rounded border border-sky-800">
                    {selectedIncident.incident_number}
                  </span>
                  <span className={`text-xs font-bold px-2 py-0.5 rounded border ${selectedIncident.severity === 'Critical'
                    ? 'bg-red-500/10 text-red-400 border-red-500/30'
                    : 'bg-orange-500/10 text-orange-400 border-orange-500/30'
                    }`}>
                    {selectedIncident.severity} Severity
                  </span>
                  <span className="text-xs text-slate-400">
                    Campaign: {selectedIncident.campaign_name || 'Targeted Campaign'}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-white mt-2">{selectedIncident.title}</h2>
                <p className="text-xs text-slate-400 mt-1">{selectedIncident.summary}</p>
              </div>
              <button
                onClick={() => setSelectedIncident(null)}
                className="p-1 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-white"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Scope Grid: Affected Users & Workstations */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold uppercase text-slate-400">
                  <Users className="w-4 h-4 text-sky-400" />
                  <span>Targeted Corporate Users ({selectedIncident.affected_users?.length || 0})</span>
                </div>
                <div className="flex flex-wrap gap-2 mt-2">
                  {selectedIncident.affected_users?.map((u, i) => (
                    <span key={i} className="px-2.5 py-1 rounded bg-slate-800/80 text-xs font-mono text-slate-200 border border-slate-700">
                      {u}
                    </span>
                  ))}
                  {(!selectedIncident.affected_users || selectedIncident.affected_users.length === 0) && (
                    <span className="text-xs text-slate-500 italic">No targeted users resolved</span>
                  )}
                </div>
              </div>

              <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl space-y-2">
                <div className="flex items-center gap-2 text-xs font-bold uppercase text-slate-400">
                  <Laptop className="w-4 h-4 text-indigo-400" />
                  <span>Mapped Endpoints & Workstations ({selectedIncident.affected_endpoints?.length || 0})</span>
                </div>
                <div className="space-y-1.5 mt-2 max-h-24 overflow-y-auto">
                  {selectedIncident.affected_endpoints?.map((ep, i) => (
                    <div key={i} className="flex items-center justify-between text-xs font-mono text-slate-300 bg-slate-900/60 p-1.5 rounded">
                      <span>{ep.hostname} ({ep.ip_address})</span>
                      <span className="text-[10px] text-slate-500">Agent {ep.agent_id}</span>
                      <span>{typeof ep === 'string' ? ep : `${ep.hostname || 'WKSTN'} (${ep.ip_address || '10.0.0.x'})`}</span>
                      <span className="text-[10px] text-slate-500">{typeof ep === 'object' && ep.agent_id ? `Agent ${ep.agent_id}` : ''}</span>
                    </div>
                  ))}
                  {(!selectedIncident.affected_endpoints || selectedIncident.affected_endpoints.length === 0) && (
                    <span className="text-xs text-slate-500 italic">No endpoint workstations mapped</span>
                  )}
                </div>
              </div>
            </div>

            {/* Correlated Shared IOC Tags */}
            <div className="p-4 bg-slate-950/40 border border-slate-800 rounded-xl space-y-2">
              <div className="flex items-center gap-2 text-xs font-bold uppercase text-slate-400">
                <Layers className="w-4 h-4 text-amber-400" />
                <span>Correlated Threat Indicators ({selectedIncident.correlated_iocs?.length || 0})</span>
              </div>
              <div className="flex flex-wrap gap-2 mt-2">
                {selectedIncident.correlated_iocs?.map((ioc, i) => (
                  <span key={i} className="px-2 py-0.5 rounded bg-amber-500/10 text-amber-300 font-mono text-xs border border-amber-500/30">
                    {ioc}
                  </span>
                ))}
                {(!selectedIncident.correlated_iocs || selectedIncident.correlated_iocs.length === 0) && (
                  <span className="text-xs text-slate-500 italic">No shared indicators</span>
                )}
              </div>
            </div>

            {/* Correlated Investigations Table */}
            <div className="space-y-2">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <FileText className="w-4 h-4 text-sky-400" />
                <span>Correlated Email Investigations ({selectedIncident.investigations?.length || 0})</span>
              </h3>
              <div className="overflow-x-auto border border-slate-800 rounded-xl">
                <table className="w-full text-left text-xs text-slate-300">
                  <thead className="bg-slate-950 text-slate-400 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Subject</th>
                      <th className="py-2.5 px-3">Sender</th>
                      <th className="py-2.5 px-3">Recipient</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Score</th>
                      <th className="py-2.5 px-3 text-right">Inspect</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {selectedIncident.investigations?.map(inv => (
                      <tr key={inv.id} className="hover:bg-slate-800/40">
                        <td className="py-2 px-3 font-medium text-white max-w-xs truncate">{inv.subject}</td>
                        <td className="py-2 px-3 font-mono text-slate-400 truncate max-w-[150px]">{inv.sender}</td>
                        <td className="py-2 px-3 font-mono text-slate-400 truncate max-w-[150px]">{inv.recipient}</td>
                        <td className="py-2 px-3">{inv.verdict}</td>
                        <td className="py-2 px-3 font-bold text-red-400">{inv.overall_risk_score}</td>
                        <td className="py-2 px-3 text-right">
                          <button
                            onClick={() => {
                              setSelectedIncident(null);
                              onSelectInvestigation(inv.id);
                            }}
                            className="text-sky-400 hover:text-sky-300 font-semibold inline-flex items-center gap-1"
                          >
                            <span>Open</span>
                            <ExternalLink className="w-3 h-3" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Chronological Incident Timeline */}
            <div className="space-y-3">
              <h3 className="text-sm font-bold text-white flex items-center gap-2">
                <Clock className="w-4 h-4 text-sky-400" />
                <span>Chronological Incident Timeline & Telemetry Attribution</span>
              </h3>
              <div className="space-y-2 border border-slate-800 rounded-xl p-4 bg-slate-950/40 max-h-60 overflow-y-auto">
                {selectedIncident.timeline?.map((ev, i) => (
                  <div key={i} className="flex items-start gap-3 text-xs border-b border-slate-800/60 pb-2.5 last:border-b-0 last:pb-0">
                    <span className="font-mono text-slate-500 whitespace-nowrap pt-0.5">
                      {ev.timestamp?.substring(11, 19) || '11:22:05'}
                    </span>
                    <div className="flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-bold text-white">{ev.title}</span>
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 font-semibold">
                          {ev.source}
                        </span>
                        {ev.telemetry_status === 'confirmed' ? (
                          <span className="inline-flex items-center gap-0.5 text-[10px] text-emerald-400 bg-emerald-500/10 px-1.5 py-0.5 rounded border border-emerald-500/30">
                            <CheckCircle2 className="w-2.5 h-2.5" /> Confirmed
                          </span>
                        ) : ev.telemetry_status === 'suspicious' ? (
                          <span className="inline-flex items-center gap-0.5 text-[10px] text-amber-400 bg-amber-500/10 px-1.5 py-0.5 rounded border border-amber-500/30">
                            <AlertTriangle className="w-2.5 h-2.5" /> Suspicious
                          </span>
                        ) : ev.telemetry_status === 'no_matching_events' ? (
                          <span className="inline-flex items-center gap-0.5 text-[10px] text-sky-400 bg-sky-500/10 px-1.5 py-0.5 rounded border border-sky-500/30">
                            <Info className="w-2.5 h-2.5" /> No Matching Events in Splunk
                          </span>
                        ) : ev.telemetry_status === 'not_configured' ? (
                          <span className="inline-flex items-center gap-0.5 text-[10px] text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700">
                            <Info className="w-2.5 h-2.5" /> Optional / Not Configured
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-0.5 text-[10px] text-slate-400 bg-slate-800/80 px-1.5 py-0.5 rounded border border-slate-700">
                            <Info className="w-2.5 h-2.5" /> Telemetry Unconfigured
                          </span>
                        )}
                      </div>
                      <p className="text-slate-400 mt-1">{ev.details}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* SOC Response Playbook with Analyst Approval */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h3 className="text-sm font-bold text-white flex items-center gap-2">
                  <Lock className="w-4 h-4 text-red-400" />
                  <span>SOC Incident Response Playbook (Analyst Approval Required)</span>
                </h3>
                <span className="text-xs text-slate-400">Strict authorization control enforced</span>
              </div>

              <div className="space-y-2 border border-slate-800 rounded-xl p-4 bg-slate-950/40">
                {selectedIncident.playbook_actions?.map(act => {
                  const isApproved = act.approval_status === 'approved';
                  const isExecuted = act.approval_status === 'executed';
                  const isPending = act.approval_status === 'pending_approval';

                  return (
                    <div key={act.id} className="p-3 rounded-lg border border-slate-800 bg-slate-900/80 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-white text-xs">{act.title}</span>
                          <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${isExecuted
                            ? 'bg-purple-500/10 text-purple-400 border border-purple-500/30'
                            : isApproved
                              ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                              : isPending
                                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                                : 'bg-red-500/10 text-red-400 border border-red-500/30'
                            }`}>
                            {(act.approval_status || '').replace('_', ' ').toUpperCase()}
                          </span>
                        </div>
                        <p className="text-xs text-slate-400 mt-1">
                          <strong className="text-slate-300">Target:</strong> {act.target} — {act.details}
                        </p>
                        {act.approved_by && (
                          <p className="text-[10px] text-slate-500 mt-0.5">
                            Signed off by {act.approved_by}
                          </p>
                        )}
                      </div>

                      {/* Action Buttons */}
                      <div className="flex items-center gap-2 self-end sm:self-center">
                        {isPending && (
                          <>
                            <button
                              onClick={() => handleApproveAction(act.id)}
                              className="px-2.5 py-1 bg-emerald-800/60 hover:bg-emerald-700 text-emerald-100 rounded text-xs font-semibold flex items-center gap-1 transition-colors"
                            >
                              <Check className="w-3 h-3" /> Approve
                            </button>
                            <button
                              onClick={() => handleRejectAction(act.id)}
                              className="px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded text-xs font-semibold flex items-center gap-1 transition-colors"
                            >
                              <X className="w-3 h-3" /> Reject
                            </button>
                          </>
                        )}
                        {isApproved && (
                          <button
                            onClick={() => handleExecuteAction(act.id)}
                            className="px-3 py-1 bg-red-800/80 hover:bg-red-700 text-white rounded text-xs font-bold flex items-center gap-1 shadow-lg shadow-red-900/30 transition-all"
                          >
                            <Play className="w-3 h-3" /> Execute Containment
                          </button>
                        )}
                        {isExecuted && (
                          <span className="text-xs font-semibold text-emerald-400 flex items-center gap-1">
                            <CheckCircle2 className="w-3.5 h-3.5" /> Executed
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end pt-4 border-t border-slate-800">
              <button
                onClick={() => setSelectedIncident(null)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm font-semibold transition-colors"
              >
                Close Incident View
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}


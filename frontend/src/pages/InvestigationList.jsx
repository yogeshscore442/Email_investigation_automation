import React, { useState, useEffect } from 'react';
import { Search, Filter, Trash2, ExternalLink, RefreshCw, AlertTriangle, ShieldCheck } from 'lucide-react';
import RiskBadge from '../components/RiskBadge';
import VerdictBadge from '../components/VerdictBadge';
import { getInvestigations, deleteInvestigation } from '../api/client';

export default function InvestigationList({ onSelectInvestigation, onNewInvestigation }) {
  const [investigations, setInvestigations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [search, setSearch] = useState('');
  const [verdictFilter, setVerdictFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');

  const fetchList = async () => {
    try {
      setLoading(true);
      setError(null);
      const params = {};
      if (verdictFilter) params.verdict = verdictFilter;
      if (riskFilter) params.risk_category = riskFilter;
      const res = await getInvestigations(params);
      setInvestigations(res.investigations || []);
    } catch (err) {
      setError('Failed to load investigations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchList();
  }, [verdictFilter, riskFilter]);

  const handleDelete = async (e, id) => {
    e.stopPropagation();
    if (!window.confirm('Delete this investigation record and its extracted artifacts?')) return;
    try {
      await deleteInvestigation(id);
      fetchList();
    } catch (err) {
      alert('Failed to delete investigation.');
    }
  };

  const filtered = investigations.filter((inv) => {
    const s = search.toLowerCase();
    return (
      (inv.subject || '').toLowerCase().includes(s) ||
      (inv.sender || '').toLowerCase().includes(s) ||
      (inv.recipient || '').toLowerCase().includes(s)
    );
  });

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Page Title & New Investigation Button */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h1 className="text-2xl font-extrabold text-white">Investigation Dossiers</h1>
          <p className="text-xs text-slate-400 mt-1">Audit log and forensic reports for all processed email evidence</p>
        </div>
        <button
          onClick={onNewInvestigation}
          className="px-4 py-2 bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white text-sm font-semibold rounded-lg shadow-md transition-all self-start sm:self-auto"
        >
          + Ingest New Email
        </button>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col md:flex-row gap-3 items-center justify-between backdrop-blur">
        <div className="relative w-full md:w-96">
          <Search className="w-4 h-4 text-slate-500 absolute left-3.5 top-3" />
          <input
            type="text"
            placeholder="Search by subject, sender, or recipient..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3.5 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex items-center gap-2.5 w-full md:w-auto">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={verdictFilter}
            onChange={(e) => setVerdictFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-sky-500"
          >
            <option value="">All Verdicts</option>
            <option value="Critical Phishing / Malware">Critical Phishing / Malware</option>
            <option value="Phishing">Phishing</option>
            <option value="Suspicious">Suspicious</option>
            <option value="Legitimate">Legitimate</option>
          </select>

          <select
            value={riskFilter}
            onChange={(e) => setRiskFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-3 py-2 focus:outline-none focus:border-sky-500"
          >
            <option value="">All Risk Tiers</option>
            <option value="Critical">Critical (80-100)</option>
            <option value="High">High (60-79)</option>
            <option value="Medium">Medium (30-59)</option>
            <option value="Low">Low (0-29)</option>
          </select>

          <button
            onClick={fetchList}
            title="Refresh list"
            className="p-2 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
          </button>
        </div>
      </div>

      {/* Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl overflow-hidden shadow-xl backdrop-blur">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950/80 text-xs font-semibold uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">Subject</th>
                <th className="py-3 px-4">Sender</th>
                <th className="py-3 px-4">Verdict</th>
                <th className="py-3 px-4">Risk Score</th>
                <th className="py-3 px-4">Artifacts</th>
                <th className="py-3 px-4">Investigated At</th>
                <th className="py-3 px-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {loading ? (
                <tr>
                  <td colSpan="7" className="text-center py-10 text-slate-400">
                    <RefreshCw className="w-6 h-6 text-sky-400 animate-spin mx-auto mb-2" />
                    <span>Loading investigations...</span>
                  </td>
                </tr>
              ) : filtered.length === 0 ? (
                <tr>
                  <td colSpan="7" className="text-center py-10 text-slate-500 italic">
                    No matching investigation records found.
                  </td>
                </tr>
              ) : (
                filtered.map((inv) => (
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
                    <td className="py-3.5 px-4 text-xs text-slate-400">
                      {inv.created_at ? new Date(inv.created_at).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            onSelectInvestigation(inv.id);
                          }}
                          className="p-1.5 hover:bg-sky-500/20 text-sky-400 rounded transition-colors"
                          title="Inspect Investigation"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </button>
                        <button
                          onClick={(e) => handleDelete(e, inv.id)}
                          className="p-1.5 hover:bg-red-500/20 text-red-400 rounded transition-colors"
                          title="Delete Record"
                        >
                          <Trash2 className="w-4 h-4" />
                        </button>
                      </div>
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


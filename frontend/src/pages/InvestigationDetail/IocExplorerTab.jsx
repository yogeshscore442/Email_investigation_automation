import React, { useState } from 'react';
import { Hash, Download, Search, Filter, CheckCircle2, ShieldAlert } from 'lucide-react';
import DefangedText from '../../components/DefangedText';
import { getIocsExportUrl } from '../../api/client';

export default function IocExplorerTab({ investigation }) {
  const iocs = investigation.iocs || [];
  const [typeFilter, setTypeFilter] = useState('');
  const [search, setSearch] = useState('');

  const filtered = iocs.filter((ioc) => {
    const matchesType = !typeFilter || ioc.ioc_type === typeFilter;
    const matchesSearch = !search || 
      ioc.ioc_value.toLowerCase().includes(search.toLowerCase()) ||
      ioc.defanged_value.toLowerCase().includes(search.toLowerCase()) ||
      (ioc.context || '').toLowerCase().includes(search.toLowerCase());
    return matchesType && matchesSearch;
  });

  const getReputationBadge = (rep) => {
    const r = (rep || 'unknown').toLowerCase();
    if (r === 'malicious') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-400 border border-red-500/30">Malicious</span>;
    } else if (r === 'suspicious') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-400 border border-amber-500/30">Suspicious</span>;
    } else if (r === 'clean') {
      return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">Clean</span>;
    }
    return <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-slate-800 text-slate-400 border border-slate-700">Unknown</span>;
  };

  return (
    <div className="space-y-6">
      {/* Top Bar with Export Options */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Hash className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">Extracted Threat Indicators ({iocs.length})</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Normalized, deduplicated, and defanged IOCs ready for SIEM, EDR blocklists, and threat hunting.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <a
            href={getIocsExportUrl(investigation.id, 'csv')}
            download
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export CSV</span>
          </a>
          <a
            href={getIocsExportUrl(investigation.id, 'json')}
            download
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Export JSON</span>
          </a>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 flex flex-col sm:flex-row gap-3 items-center justify-between backdrop-blur">
        <div className="relative w-full sm:w-80">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
          <input
            type="text"
            placeholder="Search indicator values or context..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full bg-slate-950 border border-slate-800 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
          />
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
          <Filter className="w-4 h-4 text-slate-500" />
          <select
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
            className="bg-slate-950 border border-slate-800 text-xs text-slate-300 rounded-lg px-3 py-1.5 focus:outline-none focus:border-sky-500"
          >
            <option value="">All IOC Types</option>
            <option value="ipv4">IPv4 Addresses</option>
            <option value="domain">Domains</option>
            <option value="url">URLs</option>
            <option value="email">Email Addresses</option>
            <option value="sha256">SHA256 Hashes</option>
            <option value="md5">MD5 Hashes</option>
            <option value="filename">Filenames</option>
          </select>
        </div>
      </div>

      {/* Table */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl overflow-hidden shadow-xl backdrop-blur">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-sm text-slate-300">
            <thead className="bg-slate-950 text-xs font-semibold uppercase text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4 w-28">Type</th>
                <th className="py-3 px-4">Defanged Indicator</th>
                <th className="py-3 px-4">Context</th>
                <th className="py-3 px-4 w-28 text-center">Reputation</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan="4" className="text-center py-10 text-slate-500 italic">
                    No matching indicators found.
                  </td>
                </tr>
              ) : (
                filtered.map((ioc, idx) => (
                  <tr key={idx} className="hover:bg-slate-800/40 transition-colors">
                    <td className="py-3 px-4">
                      <span className="text-xs font-mono font-bold uppercase text-slate-300 bg-slate-800 px-2 py-0.5 rounded">
                        {ioc.ioc_type}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <DefangedText text={ioc.defanged_value} rawText={ioc.ioc_value} />
                    </td>
                    <td className="py-3 px-4 text-xs text-slate-400">
                      {ioc.context}
                    </td>
                    <td className="py-3 px-4 text-center">
                      {getReputationBadge(ioc.reputation)}
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


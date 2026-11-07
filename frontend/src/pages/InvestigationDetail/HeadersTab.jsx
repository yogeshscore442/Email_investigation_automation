import React, { useState } from 'react';
import { 
  Server, ArrowDown, Clock, AlertTriangle, 
  Copy, Check, Search, Shield, Filter 
} from 'lucide-react';
import DefangedText from '../../components/DefangedText';

export default function HeadersTab({ investigation }) {
  const inv = investigation;
  const hops = inv.hops || [];
  const headers = inv.headers || [];
  const auth = inv.auth_result || {};
  const [headerSearch, setHeaderSearch] = useState('');
  const [copiedAll, setCopiedAll] = useState(false);

  const filteredHeaders = headers.filter(h => 
    h.name.toLowerCase().includes(headerSearch.toLowerCase()) || 
    h.value.toLowerCase().includes(headerSearch.toLowerCase())
  );

  const copyAllHeaders = () => {
    const text = headers.map(h => `${h.name}: ${h.value}`).join('\n');
    navigator.clipboard.writeText(text);
    setCopiedAll(true);
    setTimeout(() => setCopiedAll(false), 2000);
  };

  return (
    <div className="space-y-8">
      {/* Critical Headers Summary */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300 pb-3 border-b border-slate-800">
          Core Header Metadata
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-xs">
          <div className="space-y-1">
            <span className="text-slate-400 font-semibold uppercase">From Header</span>
            <p className="font-mono text-white bg-slate-950 p-2 rounded border border-slate-800 break-all">
              {inv.sender || 'N/A'}
            </p>
          </div>

          <div className="space-y-1">
            <span className="text-slate-400 font-semibold uppercase">Reply-To Header</span>
            <div className="flex items-center gap-2">
              <p className="font-mono text-white bg-slate-950 p-2 rounded border border-slate-800 break-all flex-1">
                {inv.reply_to || 'Same as sender'}
              </p>
              {inv.reply_to && inv.reply_to !== inv.sender && (
                <span className="shrink-0 px-2 py-1 bg-amber-500/20 text-amber-300 border border-amber-500/40 rounded text-[10px] font-bold">
                  Mismatch
                </span>
              )}
            </div>
          </div>

          <div className="space-y-1">
            <span className="text-slate-400 font-semibold uppercase">Message-ID</span>
            <p className="font-mono text-sky-400 bg-slate-950 p-2 rounded border border-slate-800 break-all">
              {inv.message_id || 'N/A'}
            </p>
          </div>

          <div className="space-y-1">
            <span className="text-slate-400 font-semibold uppercase">Originating Sending IP</span>
            <div className="bg-slate-950 p-2 rounded border border-slate-800">
              <DefangedText text={auth.x_originating_ip || 'Not explicitly declared'} />
            </div>
          </div>
        </div>
      </div>

      {/* Hop-by-Hop Transit Route Visualizer */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Server className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">Received Hop-by-Hop Transit Chain ({hops.length} Hops)</h3>
          </div>
          <span className="text-xs text-slate-400">Reconstructed chronologically from earliest originating hop to final MTA</span>
        </div>

        {hops.length === 0 ? (
          <div className="py-8 text-center text-slate-400 italic">
            No Received hops found in headers.
          </div>
        ) : (
          <div className="relative mt-6 space-y-4">
            {hops.map((hop, idx) => (
              <div key={idx} className="relative flex items-start gap-4">
                {/* Visual Step Marker */}
                <div className="flex flex-col items-center">
                  <div className="w-8 h-8 rounded-full bg-sky-500/20 border-2 border-sky-400 flex items-center justify-center text-xs font-bold text-sky-300">
                    {hop.hop_number}
                  </div>
                  {idx < hops.length - 1 && (
                    <div className="w-0.5 h-14 bg-slate-800 my-1"></div>
                  )}
                </div>

                {/* Hop Card */}
                <div className="flex-1 bg-slate-950/70 border border-slate-800 rounded-xl p-4 text-xs space-y-2">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="font-bold text-slate-200 text-sm">
                      Hop #{hop.hop_number}: {hop.by_server || 'Intermediate MTA'}
                    </span>
                    <div className="flex items-center gap-2">
                      {hop.delay_seconds > 0 && (
                        <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-semibold ${
                          hop.delay_seconds > 3600 
                            ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' 
                            : 'bg-slate-800 text-slate-300'
                        }`}>
                          <Clock className="w-3 h-3" />
                          <span>Transit Delay: {hop.delay_seconds}s</span>
                        </span>
                      )}
                      <span className="px-2 py-0.5 bg-slate-800 text-slate-400 rounded text-[10px] uppercase font-mono">
                        {hop.protocol || 'SMTP'}
                      </span>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-slate-400 pt-1">
                    <div>
                      <strong className="text-slate-300">Transmitted From:</strong> {hop.from_server || 'N/A'}
                    </div>
                    <div>
                      <strong className="text-slate-300">Relay IP:</strong> <DefangedText text={hop.ip_address} />
                    </div>
                  </div>

                  {hop.timestamp_str && (
                    <p className="text-[11px] text-slate-500 font-mono pt-1">
                      Timestamp: {hop.timestamp_str}
                    </p>
                  )}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Raw Headers Viewer */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-4 border-b border-slate-800">
          <div>
            <h3 className="text-base font-bold text-white">All Extracted Email Headers ({headers.length})</h3>
            <p className="text-xs text-slate-400">Complete raw key-value headers with search filter</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2.5 top-2.5" />
              <input
                type="text"
                placeholder="Filter headers..."
                value={headerSearch}
                onChange={(e) => setHeaderSearch(e.target.value)}
                className="bg-slate-950 border border-slate-800 rounded-lg pl-8 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500"
              />
            </div>
            <button
              onClick={copyAllHeaders}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition-colors"
            >
              {copiedAll ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copiedAll ? 'Copied!' : 'Copy All'}</span>
            </button>
          </div>
        </div>

        <div className="mt-4 overflow-x-auto max-h-[500px]">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950 text-slate-400 uppercase text-[10px] sticky top-0">
              <tr>
                <th className="py-2.5 px-3 border-b border-slate-800 w-1/4">Header Name</th>
                <th className="py-2.5 px-3 border-b border-slate-800">Value</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60">
              {filteredHeaders.map((h, i) => (
                <tr key={i} className="hover:bg-slate-950/60">
                  <td className="py-2 px-3 text-sky-400 font-semibold align-top">{h.name}</td>
                  <td className="py-2 px-3 text-slate-300 break-all whitespace-pre-wrap">{h.value}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}


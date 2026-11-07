import React from 'react';
import { Link2, AlertTriangle, ShieldAlert, CheckCircle, ExternalLink, Globe } from 'lucide-react';
import DefangedText from '../../components/DefangedText';

export default function UrlAnalysisTab({ investigation }) {
  const urls = investigation.urls || [];

  return (
    <div className="space-y-6">
      {/* Overview Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Link2 className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">Extracted Hyperlinks ({urls.length})</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            All hyperlinks extracted from HTML and plain text bodies have been safely defanged to prevent accidental execution.
          </p>
        </div>
      </div>

      {urls.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 italic">
          No external hyperlinks found in this email.
        </div>
      ) : (
        <div className="space-y-4">
          {urls.map((u, idx) => {
            const flags = u.detection_flags || [];
            const isMalicious = u.vt_reputation === 'malicious' || flags.some(f => f.severity === 'critical' || f.severity === 'high');

            return (
              <div 
                key={idx}
                className={`bg-slate-900/60 border rounded-2xl p-5 backdrop-blur transition-all ${
                  isMalicious ? 'border-red-500/40 bg-red-950/10' : 'border-slate-800'
                }`}
              >
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-slate-800/80">
                  <div className="flex items-center gap-2">
                    <span className="w-6 h-6 rounded-full bg-slate-800 flex items-center justify-center text-xs font-bold text-slate-300">
                      #{idx + 1}
                    </span>
                    <span className="text-sm font-bold text-white font-mono">{u.domain || 'Unknown Domain'}</span>
                    {u.is_ip_based && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-500/20 text-red-300 border border-red-500/30">
                        IP Host
                      </span>
                    )}
                    {u.is_shortened && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        Shortened Link
                      </span>
                    )}
                    {u.has_suspicious_tld && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/30">
                        Suspicious TLD
                      </span>
                    )}
                  </div>

                  <div className="flex items-center gap-2">
                    <span className={`text-xs px-2.5 py-1 rounded-md font-semibold border ${
                      u.vt_reputation === 'malicious'
                        ? 'bg-red-500/20 text-red-400 border-red-500/30'
                        : u.vt_reputation === 'clean'
                        ? 'bg-emerald-500/20 text-emerald-400 border-emerald-500/30'
                        : 'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      VT: {u.vt_reputation?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </div>
                </div>

                {/* Defanged URL */}
                <div className="mt-3">
                  <span className="text-[11px] font-semibold text-slate-400 uppercase block mb-1">Defanged Target:</span>
                  <DefangedText text={u.defanged_url} rawText={u.original_url} />
                </div>

                {/* Detection Flags */}
                {flags.length > 0 && (
                  <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2">
                    <span className="text-[11px] font-bold uppercase tracking-wider text-slate-400">Security Findings:</span>
                    <div className="space-y-1.5">
                      {flags.map((flag, fIdx) => (
                        <div key={fIdx} className="flex items-start gap-2 text-xs">
                          <AlertTriangle className={`w-4 h-4 shrink-0 mt-0.5 ${
                            flag.severity === 'critical' ? 'text-red-400' : flag.severity === 'high' ? 'text-orange-400' : 'text-amber-400'
                          }`} />
                          <span className="text-slate-200">
                            <strong>{flag.type}:</strong> {flag.message}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}


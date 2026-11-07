import React from 'react';
import { 
  ShieldCheck, ShieldAlert, AlertTriangle, Globe, 
  Server, Calendar, CheckCircle, XCircle, Info 
} from 'lucide-react';
import DefangedText from '../../components/DefangedText';

export default function SenderIntelTab({ investigation }) {
  const inv = investigation;
  const auth = inv.auth_result || {};
  const intel = inv.sender_intel || {};

  const getStatusBadge = (status) => {
    const s = (status || '').toLowerCase();
    if (s === 'pass') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
          <CheckCircle className="w-3.5 h-3.5" /> PASS
        </span>
      );
    } else if (s === 'fail') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">
          <XCircle className="w-3.5 h-3.5" /> FAIL
        </span>
      );
    } else if (s === 'softfail' || s === 'neutral') {
      return (
        <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-amber-500/20 text-amber-400 border border-amber-500/30">
          <AlertTriangle className="w-3.5 h-3.5" /> {s.toUpperCase()}
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-xs font-bold bg-slate-800 text-slate-400 border border-slate-700">
        <Info className="w-3.5 h-3.5" /> NONE / UNSET
      </span>
    );
  };

  return (
    <div className="space-y-6">
      {/* Typosquatting / Lookalike Impersonation Warning Banner */}
      {intel.is_lookalike && (
        <div className="p-5 bg-red-950/40 border border-red-500/50 rounded-2xl flex items-start gap-3 shadow-lg shadow-red-950/20">
          <ShieldAlert className="w-6 h-6 text-red-400 shrink-0 mt-0.5" />
          <div className="space-y-1">
            <h4 className="font-bold text-red-300 text-sm">
              Sender Domain Typosquatting / Brand Impersonation Detected!
            </h4>
            <p className="text-xs text-red-200 leading-relaxed">
              The sender's domain <code className="bg-red-900/50 px-1 py-0.5 rounded font-mono">{intel.domain}</code> closely mimics the legitimate brand <strong>{intel.targeted_brand?.toUpperCase()}</strong>.
            </p>
          </div>
        </div>
      )}

      {/* Authentication Triad (SPF, DKIM, DMARC) */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* SPF */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-sm font-bold text-white">SPF (Sender Policy)</span>
            {getStatusBadge(auth.spf_status)}
          </div>
          <p className="text-xs text-slate-400 mt-3 leading-relaxed">
            {auth.spf_details || 'No SPF evaluation record returned by receiving MTA.'}
          </p>
        </div>

        {/* DKIM */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-sm font-bold text-white">DKIM (Cryptographic Sig)</span>
            {getStatusBadge(auth.dkim_status)}
          </div>
          <p className="text-xs text-slate-400 mt-3 leading-relaxed">
            {auth.dkim_details || 'No DKIM signature verification found in headers.'}
          </p>
        </div>

        {/* DMARC */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-5 backdrop-blur">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <span className="text-sm font-bold text-white">DMARC Policy</span>
            {getStatusBadge(auth.dmarc_status)}
          </div>
          <p className="text-xs text-slate-400 mt-3 leading-relaxed">
            {auth.dmarc_details || 'No DMARC policy validation result declared.'}
          </p>
        </div>
      </div>

      {/* Domain Registration & DNS Records */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Domain Registration (RDAP) */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Globe className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">
              Sender Domain Profile ({intel.domain || 'N/A'})
            </h3>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
              <span className="text-slate-400">Domain Age:</span>
              <p className="text-base font-bold text-white mt-1">
                {intel.domain_age_days !== null && intel.domain_age_days !== undefined 
                  ? `${intel.domain_age_days} Days` 
                  : 'Unknown / Private'}
              </p>
              {intel.domain_age_days !== null && intel.domain_age_days < 30 && (
                <span className="text-[10px] text-amber-400 font-semibold block mt-1">
                  ⚠️ Newly registered domain (&lt;30 days)
                </span>
              )}
            </div>

            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
              <span className="text-slate-400">Registrar:</span>
              <p className="text-xs font-semibold text-white mt-1 truncate">
                {intel.registrar || 'Unknown'}
              </p>
            </div>
          </div>

          {/* DNS MX Records */}
          <div>
            <span className="text-xs text-slate-400 font-semibold uppercase block mb-1.5">
              Resolved MX Records ({intel.mx_records?.length || 0})
            </span>
            {intel.mx_records?.length > 0 ? (
              <div className="space-y-1">
                {intel.mx_records.map((mx, i) => (
                  <p key={i} className="text-xs font-mono bg-slate-950 p-2 rounded border border-slate-800 text-sky-300">
                    {mx}
                  </p>
                ))}
              </div>
            ) : (
              <p className="text-xs text-amber-400 italic bg-amber-950/20 p-2 rounded border border-amber-800/30">
                No active MX records resolved. Domain cannot receive return messages.
              </p>
            )}
          </div>
        </div>

        {/* Sender IP Threat Intelligence */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-4">
          <div className="flex items-center gap-2 pb-3 border-b border-slate-800">
            <Server className="w-5 h-5 text-sky-400" />
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">
              Originating Sending IP Intelligence
            </h3>
          </div>

          <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800 text-xs">
            <span className="text-slate-400">Originating IP:</span>
            <div className="mt-1">
              <DefangedText text={intel.ip_address || auth.x_originating_ip || 'None detected'} />
            </div>
          </div>

          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
              <span className="text-slate-400">Abuse Confidence:</span>
              <p className={`text-xl font-bold mt-1 ${intel.ip_abuse_score >= 50 ? 'text-red-400' : 'text-slate-200'}`}>
                {intel.ip_abuse_score || 0}%
              </p>
            </div>

            <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
              <span className="text-slate-400">Domain Reputation:</span>
              <p className="text-sm font-bold text-slate-200 capitalize mt-1">
                {intel.domain_reputation || 'Clean / Unknown'}
              </p>
            </div>
          </div>

          {intel.spf_record && (
            <div className="text-xs">
              <span className="text-slate-400 font-semibold block mb-1">Published SPF Record:</span>
              <p className="font-mono text-[11px] bg-slate-950 p-2 rounded border border-slate-800 text-slate-300 break-all">
                {intel.spf_record}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


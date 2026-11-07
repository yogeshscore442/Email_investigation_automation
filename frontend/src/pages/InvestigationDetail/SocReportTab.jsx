import React, { useState, useEffect } from 'react';
import { FileText, Download, Printer, ExternalLink, ShieldCheck, RefreshCw } from 'lucide-react';
import { getSocReport, getReportPdfUrl, getReportHtmlUrl } from '../../api/client';
import RiskBadge from '../../components/RiskBadge';
import VerdictBadge from '../../components/VerdictBadge';

export default function SocReportTab({ investigation }) {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getSocReport(investigation.id)
      .then(setReport)
      .finally(() => setLoading(false));
  }, [investigation.id]);

  const downloadJson = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `SOC_Report_${investigation.id.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 gap-3">
        <RefreshCw className="w-6 h-6 text-sky-400 animate-spin" />
        <p className="text-sm text-slate-400">Compiling SOC Investigation Report...</p>
      </div>
    );
  }

  const meta = report?.report_metadata || {};
  const s1 = report?.section_1_incident_overview || {};
  const s2 = report?.section_2_email_metadata || {};
  const s4 = report?.section_4_auth_results || {};
  const s12 = report?.section_12_mitre_attack_mapping || [];
  const s14 = report?.section_14_recommended_remediation || [];

  return (
    <div className="space-y-6">
      {/* Report Actions Header */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <FileText className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">SOC Incident Investigation Report</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Standardized 14-section technical report (Report ID: {meta.report_id} · {meta.classification})
          </p>
        </div>

        <div className="flex items-center gap-2.5 flex-wrap">
          <a
            href={getReportPdfUrl(investigation.id)}
            download
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Download PDF</span>
          </a>

          <button
            onClick={downloadJson}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Download className="w-4 h-4" />
            <span>Download JSON</span>
          </button>

          <a
            href={getReportHtmlUrl(investigation.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <ExternalLink className="w-4 h-4" />
            <span>Printable HTML</span>
          </a>
        </div>
      </div>

      {/* Rendered Live Report Document */}
      <div className="bg-slate-950 border border-slate-800 rounded-2xl p-8 shadow-2xl space-y-8 font-sans">
        {/* Document Header */}
        <div className="border-b border-slate-800 pb-6 flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <h2 className="text-xl font-black text-white tracking-tight">Security Incident Investigation Report</h2>
            <p className="text-xs text-slate-400 mt-1">
              Automated Forensic Analysis Dossier · Generated {meta.generated_at ? new Date(meta.generated_at).toLocaleString() : 'N/A'}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <VerdictBadge verdict={s1.final_verdict} size="lg" />
            <RiskBadge score={s1.overall_risk_score} category={s1.risk_category} size="lg" />
          </div>
        </div>

        {/* Section 1: Executive Overview */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 border-b border-slate-800/80 pb-1">
            Section 1: Incident & Threat Overview
          </h4>
          <p className="text-xs text-slate-300 leading-relaxed bg-slate-900/60 p-4 rounded-xl border border-slate-800">
            {s1.executive_summary || 'No overview summary available.'}
          </p>
        </div>

        {/* Section 2: Metadata */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 border-b border-slate-800/80 pb-1">
            Section 2: Forensic Email Metadata
          </h4>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs">
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Subject:</span>
              <span className="font-semibold text-white">{s2.subject}</span>
            </div>
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Sender (From):</span>
              <span className="font-mono text-slate-200">{s2.sender}</span>
            </div>
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Recipient (To):</span>
              <span className="font-mono text-slate-200">{s2.recipient}</span>
            </div>
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800/80">
              <span className="text-slate-400 block mb-0.5">Message-ID:</span>
              <span className="font-mono text-slate-200 break-all">{s2.message_id || 'N/A'}</span>
            </div>
          </div>
        </div>

        {/* Section 4: Authentication */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 border-b border-slate-800/80 pb-1">
            Section 4: Authentication Audit (SPF, DKIM, DMARC)
          </h4>
          <div className="grid grid-cols-3 gap-3 text-xs text-center">
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800">
              <span className="text-slate-400 block">SPF</span>
              <span className="font-bold text-white uppercase text-sm mt-1 block">{s4.spf_status || 'NONE'}</span>
            </div>
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800">
              <span className="text-slate-400 block">DKIM</span>
              <span className="font-bold text-white uppercase text-sm mt-1 block">{s4.dkim_status || 'NONE'}</span>
            </div>
            <div className="p-3 bg-slate-900/40 rounded-lg border border-slate-800">
              <span className="text-slate-400 block">DMARC</span>
              <span className="font-bold text-white uppercase text-sm mt-1 block">{s4.dmarc_status || 'NONE'}</span>
            </div>
          </div>
        </div>

        {/* Section 12: MITRE ATT&CK */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 border-b border-slate-800/80 pb-1">
            Section 12: MITRE ATT&CK Alignment
          </h4>
          <div className="space-y-2 text-xs">
            {s12.length === 0 ? (
              <p className="text-slate-500 italic">No adversary techniques identified.</p>
            ) : (
              s12.map((m, idx) => (
                <div key={idx} className="p-2.5 bg-slate-900/40 border border-slate-800 rounded-lg flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-sky-400">{m.technique_id}</span>
                    <span className="font-semibold text-slate-200">{m.technique_name}</span>
                  </div>
                  <span className="text-slate-400 font-mono text-[11px]">{m.tactic}</span>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Section 14: Playbook */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold uppercase tracking-wider text-sky-400 border-b border-slate-800/80 pb-1">
            Section 14: Prescribed Remediation Actions
          </h4>
          <div className="space-y-2 text-xs">
            {s14.length === 0 ? (
              <p className="text-slate-500 italic">Routine monitoring only.</p>
            ) : (
              s14.map((act, idx) => (
                <div key={idx} className="p-3 bg-slate-900/40 border border-slate-800 rounded-lg flex items-start justify-between gap-3">
                  <div>
                    <span className="font-bold text-white block">{act.action}</span>
                    <span className="text-slate-300 block mt-0.5">{act.details}</span>
                  </div>
                  <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold bg-slate-800 text-slate-300 shrink-0">
                    {act.priority}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}


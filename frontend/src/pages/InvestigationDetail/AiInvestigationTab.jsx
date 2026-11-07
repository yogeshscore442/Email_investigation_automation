import React from 'react';
import { Sparkles, Shield, Compass, CheckSquare, Layers, AlertTriangle } from 'lucide-react';

export default function AiInvestigationTab({ investigation }) {
  const ai = investigation.ai_analysis || {};
  const mitre = ai.mitre_attack || [];
  const actions = ai.recommended_actions || [];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Sparkles className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">AI-Assisted Investigation & MITRE Mapping</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Engineered threat interpretation, MITRE ATT&CK tactic alignment, and guided SOC containment playbook.
          </p>
        </div>
        <span className="px-3 py-1 bg-sky-500/10 text-sky-400 border border-sky-500/30 rounded-full text-xs font-semibold">
          Model: {ai.model_used || 'Heuristic Security Engine'}
        </span>
      </div>

      {/* AI Forensic Technical Breakdown */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur space-y-4">
        <h4 className="text-sm font-bold uppercase tracking-wider text-slate-300 pb-3 border-b border-slate-800">
          Forensic Technical Summary
        </h4>
        <div className="prose prose-invert max-w-none text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed bg-slate-950/80 p-4 rounded-xl border border-slate-800">
          {ai.technical_summary || 'No technical summary generated.'}
        </div>
      </div>

      {/* MITRE ATT&CK Matrix Mapping */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex items-center gap-2 pb-4 border-b border-slate-800">
          <Compass className="w-5 h-5 text-sky-400" />
          <div>
            <h4 className="text-base font-bold text-white">MITRE ATT&CK Framework Mapping ({mitre.length} Techniques)</h4>
            <p className="text-xs text-slate-400">Mapped adversarial techniques observed in email artifacts</p>
          </div>
        </div>

        {mitre.length === 0 ? (
          <div className="py-8 text-center text-slate-400 italic">
            No adversary techniques identified.
          </div>
        ) : (
          <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
            {mitre.map((m, idx) => (
              <div key={idx} className="bg-slate-950/70 border border-slate-800 rounded-xl p-4 space-y-2">
                <div className="flex items-center justify-between">
                  <span className="px-2 py-0.5 bg-sky-500/20 text-sky-400 font-mono text-xs font-bold rounded border border-sky-500/30">
                    {m.technique_id}
                  </span>
                  <span className="px-2 py-0.5 bg-indigo-500/20 text-indigo-300 text-[10px] font-bold uppercase rounded border border-indigo-500/30">
                    {m.tactic}
                  </span>
                </div>
                <h5 className="font-bold text-sm text-white">{m.technique_name}</h5>
                <p className="text-xs text-slate-400 leading-relaxed">{m.description}</p>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Recommended SOC Playbook & Remediation */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex items-center gap-2 pb-4 border-b border-slate-800">
          <CheckSquare className="w-5 h-5 text-sky-400" />
          <div>
            <h4 className="text-base font-bold text-white">Recommended SOC Remediation Playbook ({actions.length} Steps)</h4>
            <p className="text-xs text-slate-400">Prescriptive triage, containment, and enterprise eradication steps</p>
          </div>
        </div>

        {actions.length === 0 ? (
          <div className="py-8 text-center text-slate-400 italic">
            No remediation steps required. Routine monitoring recommended.
          </div>
        ) : (
          <div className="mt-4 space-y-3">
            {actions.map((act, idx) => (
              <div key={idx} className="p-4 bg-slate-950/70 border border-slate-800 rounded-xl flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-white">{act.action}</span>
                    <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded border ${
                      act.priority === 'Critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      act.priority === 'High' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      {act.priority} Priority
                    </span>
                  </div>
                  <p className="text-xs text-slate-300">{act.details}</p>
                </div>
                <span className="px-2.5 py-1 bg-slate-900 text-slate-400 border border-slate-800 rounded text-[11px] font-semibold shrink-0 self-start">
                  Phase: {act.phase}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}


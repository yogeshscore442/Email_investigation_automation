import React, { useState } from 'react';
import { 
  ShieldAlert, ShieldCheck, AlertTriangle, Skull, 
  FileCheck, Eye, ListFilter, Activity, AlertCircle 
} from 'lucide-react';
import RiskBadge from '../../components/RiskBadge';
import VerdictBadge from '../../components/VerdictBadge';

export default function OverviewTab({ investigation }) {
  const [bodyView, setBodyView] = useState('html'); // 'html' | 'plain'
  const inv = investigation;
  const breakdown = inv.risk_breakdown || {};
  const rules = inv.rules || [];
  const ai = inv.ai_analysis || {};

  const score = inv.overall_risk_score || 0;
  const scoreColor = score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 30 ? 'text-amber-400' : 'text-emerald-400';
  const progressBg = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 30 ? 'bg-amber-500' : 'bg-emerald-500';

  return (
    <div className="space-y-6">
      {/* Top Threat Banner */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Risk Score Gauge & Category Breakdown */}
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
          <div className="flex items-center justify-between pb-3 border-b border-slate-800">
            <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">Forensic Risk Score</h3>
            <RiskBadge score={score} category={inv.risk_category} size="sm" />
          </div>

          <div className="flex items-center justify-center py-6">
            <div className="text-center">
              <span className={`text-6xl font-black ${scoreColor}`}>{score}</span>
              <span className="text-xl font-bold text-slate-500"> / 100</span>
              <p className="text-xs uppercase tracking-widest font-bold text-slate-400 mt-1">
                {inv.risk_category} Risk Rating
              </p>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden">
            <div 
              className={`h-full rounded-full transition-all duration-700 ${progressBg}`}
              style={{ width: `${Math.min(100, Math.max(5, score))}%` }}
            ></div>
          </div>

          {/* Category Contributions */}
          <div className="mt-5 space-y-2 text-xs">
            <div className="flex justify-between text-slate-400">
              <span>Authentication (SPF/DMARC)</span>
              <span className="font-semibold text-slate-200">+{breakdown.auth_score || 0} pts</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Identity & Lookalike Domains</span>
              <span className="font-semibold text-slate-200">+{breakdown.sender_score || 0} pts</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>URL Threats & Obfuscation</span>
              <span className="font-semibold text-slate-200">+{breakdown.url_score || 0} pts</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Attachment Forensics & Macros</span>
              <span className="font-semibold text-slate-200">+{breakdown.attachment_score || 0} pts</span>
            </div>
            <div className="flex justify-between text-slate-400">
              <span>Content, Urgency & Forms</span>
              <span className="font-semibold text-slate-200">+{breakdown.content_score || 0} pts</span>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="lg:col-span-2 bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Activity className="w-4 h-4 text-sky-400" />
                <h3 className="text-sm font-bold uppercase tracking-wider text-slate-300">Executive Threat Assessment</h3>
              </div>
              <span className="text-xs text-slate-400">{ai.model_used || 'Heuristic Security Engine'}</span>
            </div>

            <p className="mt-4 text-sm text-slate-200 leading-relaxed">
              {ai.executive_summary || 'Analysis completed with no executive summary available.'}
            </p>
          </div>

          <div className="mt-6 pt-4 border-t border-slate-800/80 grid grid-cols-2 sm:grid-cols-4 gap-3 text-center">
            <div className="p-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80">
              <p className="text-[11px] text-slate-400">Transit Hops</p>
              <p className="text-lg font-bold text-white mt-0.5">{inv.hops?.length || 0}</p>
            </div>
            <div className="p-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80">
              <p className="text-[11px] text-slate-400">Hyperlinks</p>
              <p className="text-lg font-bold text-sky-400 mt-0.5">{inv.urls?.length || 0}</p>
            </div>
            <div className="p-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80">
              <p className="text-[11px] text-slate-400">Attachments</p>
              <p className="text-lg font-bold text-amber-400 mt-0.5">{inv.attachments?.length || 0}</p>
            </div>
            <div className="p-2.5 bg-slate-950/60 rounded-xl border border-slate-800/80">
              <p className="text-[11px] text-slate-400">Rule Triggers</p>
              <p className="text-lg font-bold text-red-400 mt-0.5">{rules.length}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Triggered Detection Rules */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <ListFilter className="w-4 h-4 text-sky-400" />
            <h3 className="text-base font-bold text-white">Triggered Security Rules ({rules.length})</h3>
          </div>
          <span className="text-xs text-slate-400">Automated multi-layer heuristic and behavioral detections</span>
        </div>

        {rules.length === 0 ? (
          <div className="py-8 text-center text-slate-400 italic">
            No malicious or suspicious detection rules triggered. Clean baseline profile.
          </div>
        ) : (
          <div className="divide-y divide-slate-800/80 mt-2">
            {rules.map((rule, idx) => (
              <div key={idx} className="py-4 flex flex-col md:flex-row md:items-start justify-between gap-3">
                <div className="space-y-1">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-bold text-sm text-white">{rule.rule_name}</span>
                    <span className={`text-[10px] font-bold uppercase px-2 py-0.5 rounded border ${
                      rule.severity === 'critical' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                      rule.severity === 'high' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                      rule.severity === 'medium' ? 'bg-amber-500/20 text-amber-400 border-amber-500/30' :
                      'bg-slate-800 text-slate-400 border-slate-700'
                    }`}>
                      {rule.severity} (+{rule.weight} pts)
                    </span>
                    <span className="text-xs font-mono text-slate-500">[{rule.rule_id}]</span>
                  </div>
                  <p className="text-xs text-slate-300">{rule.description}</p>
                  <p className="text-xs text-sky-400/90 font-mono bg-slate-950/60 p-2 rounded border border-slate-800/80 mt-1.5 break-all">
                    <strong>Evidence:</strong> {rule.evidence}
                  </p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Sanitized Email Content Preview */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur">
        <div className="flex items-center justify-between pb-4 border-b border-slate-800">
          <div className="flex items-center gap-2">
            <Eye className="w-4 h-4 text-sky-400" />
            <h3 className="text-base font-bold text-white">Sanitized Email Content Preview</h3>
          </div>
          <div className="flex gap-1 bg-slate-950 p-1 rounded-lg border border-slate-800">
            <button
              onClick={() => setBodyView('html')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                bodyView === 'html' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Sanitized HTML (Defanged)
            </button>
            <button
              onClick={() => setBodyView('plain')}
              className={`px-3 py-1 text-xs font-semibold rounded-md transition-all ${
                bodyView === 'plain' ? 'bg-sky-500/20 text-sky-300 border border-sky-500/30' : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              Plain Text Body
            </button>
          </div>
        </div>

        <div className="mt-4 p-5 bg-slate-950/80 border border-slate-800 rounded-xl overflow-auto max-h-[450px]">
          {bodyView === 'html' ? (
            <div 
              className="prose prose-invert max-w-none text-sm text-slate-300 leading-relaxed"
              dangerouslySetInnerHTML={{ __html: inv.sanitized_html || '<p><em>No HTML body extracted.</em></p>' }}
            />
          ) : (
            <pre className="text-xs font-mono text-slate-300 whitespace-pre-wrap leading-relaxed">
              {inv.plain_body || 'No plain text content extracted.'}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}


import React from 'react';
import { Paperclip, AlertTriangle, ShieldAlert, FileCode, CheckCircle, Hash } from 'lucide-react';
import DefangedText from '../../components/DefangedText';

export default function AttachmentTab({ investigation }) {
  const attachments = investigation.attachments || [];

  return (
    <div className="space-y-6">
      {/* Banner */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-6 backdrop-blur flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Paperclip className="w-5 h-5 text-sky-400" />
            <h3 className="text-base font-bold text-white">Attachment Forensics ({attachments.length})</h3>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Static forensic inspection, magic byte verification, macro stream extraction, and cryptographic hash analysis.
          </p>
        </div>
      </div>

      {attachments.length === 0 ? (
        <div className="bg-slate-900/60 border border-slate-800 rounded-2xl p-12 text-center text-slate-400 italic">
          No file attachments present in this email.
        </div>
      ) : (
        <div className="space-y-5">
          {attachments.map((att, idx) => {
            const isHazard = att.has_macro || att.is_dangerous_extension || att.is_mismatch || att.vt_reputation === 'malicious';
            const findings = att.macro_findings || [];

            return (
              <div 
                key={idx}
                className={`bg-slate-900/60 border rounded-2xl p-6 backdrop-blur space-y-4 ${
                  isHazard ? 'border-red-500/50 bg-red-950/10' : 'border-slate-800'
                }`}
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-800">
                  <div className="flex items-center gap-3">
                    <div className={`p-2.5 rounded-xl border ${
                      isHazard ? 'bg-red-500/20 text-red-400 border-red-500/40' : 'bg-slate-800 text-slate-300 border-slate-700'
                    }`}>
                      <FileCode className="w-6 h-6" />
                    </div>
                    <div>
                      <h4 className="font-bold text-white text-base font-mono">{att.filename}</h4>
                      <p className="text-xs text-slate-400">
                        Size: {(att.file_size / 1024).toFixed(1)} KB ({att.file_size} bytes)
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 flex-wrap">
                    {att.has_macro && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold uppercase bg-red-500/20 text-red-300 border border-red-500/40">
                        Weaponized Macro
                      </span>
                    )}
                    {att.is_mismatch && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold uppercase bg-orange-500/20 text-orange-300 border border-orange-500/40">
                        MIME Mismatch
                      </span>
                    )}
                    {att.is_dangerous_extension && (
                      <span className="px-2.5 py-1 rounded text-xs font-bold uppercase bg-amber-500/20 text-amber-300 border border-amber-500/40">
                        High-Risk File Type
                      </span>
                    )}
                    <span className="px-2.5 py-1 rounded text-xs font-semibold bg-slate-800 text-slate-300 border border-slate-700">
                      VT: {att.vt_reputation?.toUpperCase() || 'UNKNOWN'}
                    </span>
                  </div>
                </div>

                {/* MIME Details */}
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                    <span className="text-slate-400 font-semibold uppercase">Reported MIME:</span>
                    <p className="font-mono text-slate-300 mt-1">{att.reported_mime || 'application/octet-stream'}</p>
                  </div>
                  <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800">
                    <span className="text-slate-400 font-semibold uppercase">Detected Magic MIME:</span>
                    <p className="font-mono text-slate-300 mt-1">{att.detected_mime || 'application/octet-stream'}</p>
                  </div>
                </div>

                {/* Hashes */}
                <div className="space-y-2 text-xs">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 bg-slate-950/60 rounded-xl border border-slate-800 gap-2">
                    <span className="text-slate-400 font-semibold uppercase shrink-0">SHA256:</span>
                    <DefangedText text={att.sha256} />
                  </div>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between p-2.5 bg-slate-950/60 rounded-xl border border-slate-800 gap-2">
                    <span className="text-slate-400 font-semibold uppercase shrink-0">MD5:</span>
                    <DefangedText text={att.md5} />
                  </div>
                </div>

                {/* Macro Findings */}
                {findings.length > 0 && (
                  <div className="p-4 bg-red-950/30 border border-red-500/30 rounded-xl space-y-2">
                    <span className="text-xs font-bold text-red-300 uppercase tracking-wider block">
                      VBA / Macro Execution Telemetry:
                    </span>
                    <ul className="list-disc list-inside text-xs text-red-200/90 space-y-1 font-mono">
                      {findings.map((f, fIdx) => (
                        <li key={fIdx}>{f}</li>
                      ))}
                    </ul>
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


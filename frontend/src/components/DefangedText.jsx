import React, { useState } from 'react';
import { Copy, Check } from 'lucide-react';

export default function DefangedText({ text, showCopy = true, copyRaw = false, rawText = '' }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = (e) => {
    e.stopPropagation();
    const toCopy = copyRaw && rawText ? rawText : text;
    navigator.clipboard.writeText(toCopy || '');
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (!text) return <span className="text-slate-500 italic">None</span>;

  return (
    <span className="inline-flex items-center gap-1.5 group font-mono text-sky-400 bg-slate-900/90 px-2 py-0.5 rounded border border-slate-800 text-xs break-all">
      <span>{text}</span>
      {showCopy && (
        <button
          onClick={handleCopy}
          title={copied ? "Copied!" : "Copy indicator"}
          className="text-slate-500 hover:text-slate-200 transition-colors focus:outline-none ml-1 p-0.5"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5 opacity-60 group-hover:opacity-100" />}
        </button>
      )}
    </span>
  );
}


import React from 'react';
import { ShieldCheck, AlertTriangle, ShieldAlert, Skull } from 'lucide-react';

export default function VerdictBadge({ verdict = 'Legitimate', size = 'md' }) {
  let config = {
    color: 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30',
    icon: ShieldCheck,
    label: 'Legitimate'
  };

  const v = (verdict || '').toLowerCase();
  if (v.includes('critical') || v.includes('malware')) {
    config = {
      color: 'bg-red-500/20 text-red-400 border-red-500/40',
      icon: Skull,
      label: 'Critical Phishing / Malware'
    };
  } else if (v.includes('phishing')) {
    config = {
      color: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
      icon: ShieldAlert,
      label: 'Phishing'
    };
  } else if (v.includes('suspicious')) {
    config = {
      color: 'bg-amber-500/20 text-amber-400 border-amber-500/40',
      icon: AlertTriangle,
      label: 'Suspicious'
    };
  }

  const Icon = config.icon;
  const padding = size === 'lg' ? 'px-3.5 py-1.5 text-sm' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-bold rounded-md border ${config.color} ${padding}`}>
      <Icon className={size === 'lg' ? 'w-4 h-4' : 'w-3.5 h-3.5'} />
      <span>{config.label}</span>
    </span>
  );
}


import React from 'react';

export default function RiskBadge({ score = 0, category = 'Low', size = 'md' }) {
  let colorStyles = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
  let dotColor = 'bg-emerald-400';

  if (category === 'Critical' || score >= 80) {
    colorStyles = 'bg-red-500/20 text-red-400 border-red-500/40 animate-pulse';
    dotColor = 'bg-red-400';
  } else if (category === 'High' || score >= 60) {
    colorStyles = 'bg-orange-500/20 text-orange-400 border-orange-500/40';
    dotColor = 'bg-orange-400';
  } else if (category === 'Medium' || score >= 30) {
    colorStyles = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
    dotColor = 'bg-amber-400';
  }

  const sizeClasses = size === 'lg' ? 'px-3 py-1.5 text-sm' : 'px-2 py-0.5 text-xs';

  return (
    <span className={`inline-flex items-center gap-1.5 font-semibold rounded-full border ${colorStyles} ${sizeClasses}`}>
      <span className={`w-2 h-2 rounded-full ${dotColor}`}></span>
      <span>{category} ({score}/100)</span>
    </span>
  );
}


import React from 'react';

export default function MetricCard({ title, value, icon: Icon, color = 'sky', subtitle }) {
  const colorMap = {
    sky: 'border-sky-500/30 bg-sky-500/10 text-sky-400',
    indigo: 'border-indigo-500/30 bg-indigo-500/10 text-indigo-400',
    blue: 'border-blue-500/30 bg-blue-500/10 text-blue-400',
    cyan: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-400',
    red: 'border-red-500/30 bg-red-500/10 text-red-400',
    rose: 'border-rose-500/30 bg-rose-500/10 text-rose-400',
    orange: 'border-orange-500/30 bg-orange-500/10 text-orange-400',
    emerald: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-400',
    amber: 'border-amber-500/30 bg-amber-500/10 text-amber-400',
    purple: 'border-purple-500/30 bg-purple-500/10 text-purple-400'
  };

  const themeClasses = colorMap[color] || colorMap.sky;
  const bottomBorderColor = (themeClasses.split(' ')[0]) || 'border-sky-500/30';

  return (
    <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-5 relative overflow-hidden shadow-lg backdrop-blur hover:border-slate-700 transition-all">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-semibold uppercase tracking-wider text-slate-400">{title}</p>
          <h3 className="text-3xl font-extrabold text-white mt-1.5">{value ?? 0}</h3>
          {subtitle && <p className="text-xs text-slate-400 mt-1">{subtitle}</p>}
        </div>
        <div className={`p-3 rounded-xl border ${themeClasses}`}>
          {Icon && <Icon className="w-6 h-6" />}
        </div>
      </div>
      <div className={`absolute bottom-0 left-0 right-0 h-0.5 ${bottomBorderColor}`}></div>
    </div>
  );
}

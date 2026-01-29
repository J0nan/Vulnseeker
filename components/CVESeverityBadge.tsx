import React from 'react';

interface CVESeverityBadgeProps {
  score: number | null;
}

export const CVESeverityBadge: React.FC<CVESeverityBadgeProps> = ({ score }) => {
  if (score === null || score === undefined) {
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-slate-700 text-slate-300">
        N/A
      </span>
    );
  }

  let colorClass = "bg-slate-700 text-slate-300";
  let label = "Unknown";

  if (score >= 9.0) {
    colorClass = "bg-purple-900/50 text-purple-200 border border-purple-700/50";
    label = "Critical";
  } else if (score >= 7.0) {
    colorClass = "bg-red-900/50 text-red-200 border border-red-700/50";
    label = "High";
  } else if (score >= 4.0) {
    colorClass = "bg-orange-900/50 text-orange-200 border border-orange-700/50";
    label = "Medium";
  } else {
    colorClass = "bg-green-900/50 text-green-200 border border-green-700/50";
    label = "Low";
  }

  return (
    <div className={`flex flex-col items-center justify-center min-w-[60px] p-2 rounded-lg ${colorClass}`}>
      <span className="text-lg font-bold font-mono leading-none">{score.toFixed(1)}</span>
      <span className="text-[10px] uppercase tracking-wider font-semibold opacity-80 mt-1">{label}</span>
    </div>
  );
};

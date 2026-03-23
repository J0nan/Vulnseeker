import React, { useEffect, useRef, useState } from 'react';

interface CVESeverityBadgeProps {
  score: number | null;
  label?: string;
  subtitle?: string;
  vector?: string | null;
}

export const CVESeverityBadge: React.FC<CVESeverityBadgeProps> = ({ score, label: scoreLabel, subtitle, vector }) => {
  const [copyFeedback, setCopyFeedback] = useState<{ status: 'success' | 'error'; message: string } | null>(null);
  const feedbackTimerRef = useRef<number | null>(null);

  let colorClass = "bg-slate-700 text-slate-300";
  let label = "Unknown";

  if (score !== null && score !== undefined && score >= 9.0) {
    colorClass = "bg-purple-900/50 text-purple-200 border border-purple-700/50";
    label = "Critical";
  } else if (score !== null && score !== undefined && score >= 7.0) {
    colorClass = "bg-red-900/50 text-red-200 border border-red-700/50";
    label = "High";
  } else if (score !== null && score !== undefined && score >= 4.0) {
    colorClass = "bg-orange-900/50 text-orange-200 border border-orange-700/50";
    label = "Medium";
  } else if (score !== null && score !== undefined) {
    colorClass = "bg-green-900/50 text-green-200 border border-green-700/50";
    label = "Low";
  }

  const vectorValue = vector && vector.trim().length > 0 ? vector : 'Vector unavailable';
  const wrapperLabel = scoreLabel;

  useEffect(() => {
    return () => {
      if (feedbackTimerRef.current !== null) {
        window.clearTimeout(feedbackTimerRef.current);
      }
    };
  }, []);

  const showCopyFeedback = (status: 'success' | 'error', message: string) => {
    setCopyFeedback({ status, message });

    if (feedbackTimerRef.current !== null) {
      window.clearTimeout(feedbackTimerRef.current);
    }

    feedbackTimerRef.current = window.setTimeout(() => {
      setCopyFeedback(null);
      feedbackTimerRef.current = null;
    }, 1800);
  };

  const handleCopyVector = async () => {
    if (!vector || vector.trim().length === 0) {
      showCopyFeedback('error', 'Vector unavailable');
      return;
    }

    try {
      await navigator.clipboard.writeText(vector);
      showCopyFeedback('success', 'CVSS vector copied');
    } catch {
      showCopyFeedback('error', 'Copy failed');
    }
  };

  return (
    <div className="relative group/cvss flex flex-col items-center gap-1 outline-none">
      {wrapperLabel && (
        <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">{wrapperLabel}</span>
      )}
      <button
        type="button"
        onClick={handleCopyVector}
        className={`flex flex-col items-center justify-center min-w-[60px] p-2 rounded-lg transition-colors hover:brightness-110 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-400/80 ${colorClass}`}
        title={vector && vector.trim().length > 0 ? 'Copy CVSS vector' : 'Vector unavailable'}
      >
        <span className="text-lg font-bold font-mono leading-none">
          {score === null || score === undefined ? 'N/A' : score.toFixed(1)}
        </span>
        <span className="text-[10px] uppercase tracking-wider font-semibold opacity-80 mt-1">{label}</span>
      </button>
      {subtitle && (
        <span className="text-[10px] text-slate-500">{subtitle}</span>
      )}
      <div className="relative h-3 w-full">
        <span
          role="status"
          aria-live="polite"
          className={`pointer-events-none absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 whitespace-nowrap text-[10px] font-medium transition-opacity ${copyFeedback ? 'opacity-100' : 'opacity-0'} ${copyFeedback?.status === 'success' ? 'text-emerald-300' : copyFeedback?.status === 'error' ? 'text-red-300' : 'text-transparent'}`}
        >
          {copyFeedback?.message ?? '\u00A0'}
        </span>
      </div>

      <div className="pointer-events-none absolute left-full ml-2 top-0 z-30 w-80 opacity-0 transition-opacity group-hover/cvss:opacity-100 group-focus-within/cvss:opacity-100 group-hover/cvss:pointer-events-auto group-focus-within/cvss:pointer-events-auto">
        <div className="rounded-lg border border-slate-700 bg-slate-950/95 p-2 shadow-xl">
          <p className="mb-1 text-[10px] uppercase tracking-wide text-slate-400">CVSS Vector (select/copy)</p>
          <textarea
            readOnly
            value={vectorValue}
            rows={2}
            className="w-full resize-none rounded border border-slate-700 bg-slate-900 p-2 text-[11px] font-mono text-slate-200 focus:outline-none"
          />
        </div>
      </div>
    </div>
  );
};

import React, { useState, useMemo } from 'react';
import { CVE } from '../types';
import { CVESeverityBadge } from './CVESeverityBadge';
import { ChevronDown, ChevronUp, Calendar, Server, Box, AlertOctagon, Trash2 } from 'lucide-react';

interface CVECardProps {
  cve: CVE;
  onDelete: () => void;
}

export const CVECard: React.FC<CVECardProps> = ({ cve, onDelete }) => {
  const [expanded, setExpanded] = useState(true);
  const [showAllConfig, setShowAllConfig] = useState(false);
  
  const isRejected = cve.vulnStatus === 'Rejected' || cve.vulnStatus === 'REJECTED';
  const configLimit = 5;
  const configCount = cve.vulnerable_configuration.length;
  const hasManyConfigs = configCount > configLimit;

  const displayedConfig = useMemo(() => {
    if (hasManyConfigs && !showAllConfig) {
        return cve.vulnerable_configuration.slice(0, configLimit);
    }
    return cve.vulnerable_configuration;
  }, [cve.vulnerable_configuration, hasManyConfigs, showAllConfig]);

  const formattedDate = new Date(cve.Published).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric'
  });

  const fallbackCvssData = useMemo(() => {
    if (cve.cvssV31 !== null && cve.cvssV31 !== undefined) {
      return {
        score: cve.cvssV31,
        label: 'CVSS v3.1',
        source: 'v3.1',
        vector: cve.cvssVectorV31 ?? null
      };
    }

    if (cve.cvssV30 !== null && cve.cvssV30 !== undefined) {
      return {
        score: cve.cvssV30,
        label: 'CVSS v3.0',
        source: 'v3.0',
        vector: cve.cvssVectorV30 ?? null
      };
    }

    if (cve.cvssV20 !== null && cve.cvssV20 !== undefined) {
      return {
        score: cve.cvssV20,
        label: 'CVSS v2.0',
        source: 'v2.0',
        vector: cve.cvssVectorV20 ?? null
      };
    }

    return {
      score: null,
      label: 'CVSS v3.1/v3.0/v2.0',
      source: 'none',
      vector: null
    };
  }, [cve.cvssV31, cve.cvssV30, cve.cvssV20, cve.cvssVectorV31, cve.cvssVectorV30, cve.cvssVectorV20]);

  const fallbackCvssScore = fallbackCvssData.score;
  const fallbackCvssLabel = fallbackCvssData.label;

  return (
    <div className={`bg-slate-800/50 border border-white/5 rounded-xl p-5 hover:border-blue-500/30 transition-all duration-300 shadow-lg hover:shadow-xl group ${isRejected ? 'opacity-75 grayscale-[0.5] border-red-900/20' : ''}`}>
      <div className="flex items-start gap-4">
        {/* Severity Score Column */}
        <div className="shrink-0 flex flex-col gap-2 items-start">
          <div className="flex flex-row flex-wrap gap-3 items-start">
            <CVESeverityBadge
              score={cve.cvssV40 ?? null}
              label="CVSS v4.0"
              vector={cve.cvssVectorV40 ?? null}
            />
            <CVESeverityBadge
              score={fallbackCvssData.score}
              label={fallbackCvssData.label}
              vector={fallbackCvssData.vector}
            />
          </div>
          {isRejected && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-900/30 text-red-400 border border-red-800/50">
              <AlertOctagon className="w-3 h-3" /> Rejected
            </span>
          )}
        </div>

        {/* Content Column */}
        <div className="flex-1 min-w-0">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-2">
            <div className="flex items-center gap-2 min-w-0">
              <h3 className={`text-lg font-bold font-mono tracking-tight transition-colors ${isRejected ? 'text-slate-400 line-through decoration-red-500/50' : 'text-blue-400 group-hover:text-blue-300'}`}>
                {cve.id}
              </h3>
              <a
                href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Open ${cve.id} on MITRE`}
                className="shrink-0 inline-flex items-center px-2 py-1 rounded border border-slate-600/60 text-xs font-semibold text-slate-200 hover:text-white hover:border-blue-500/60 hover:bg-blue-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/70"
              >
                MITRE
              </a>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`Open ${cve.id} on NIST NVD`}
                className="shrink-0 inline-flex items-center px-2 py-1 rounded border border-slate-600/60 text-xs font-semibold text-slate-200 hover:text-white hover:border-blue-500/60 hover:bg-blue-500/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-blue-500/70"
              >
                NIST
              </a>
            </div>
            <div className="flex items-center gap-2">
                <div className="flex items-center gap-3 text-xs text-slate-400">
                <span className="flex items-center gap-1 bg-slate-900/50 px-2 py-1 rounded">
                    <Calendar className="w-3 h-3" />
                    {formattedDate}
                </span>
                </div>
                <button 
                    onClick={onDelete}
                    className="p-1 hover:bg-red-500/20 rounded-full text-slate-500 hover:text-red-400 transition-colors ml-1"
                    title="Remove from view"
                >
                    <Trash2 className="w-4 h-4" />
                </button>
            </div>
          </div>
          
          <p className="text-slate-300 text-sm leading-relaxed mb-4 line-clamp-3 md:line-clamp-none">
            {cve.summary}
          </p>

          <div className="flex flex-wrap items-center gap-2 mb-4 text-xs">
            {(cve.cvssV40 !== null && cve.cvssV40 !== undefined) && (
              <span className="px-2 py-1 rounded bg-blue-900/30 text-blue-300 border border-blue-800/40 font-mono">
                CVSS v4.0: {cve.cvssV40.toFixed(1)}
              </span>
            )}
            {(fallbackCvssScore !== null && fallbackCvssScore !== undefined) && (
              <span className="px-2 py-1 rounded bg-slate-700/60 text-slate-200 border border-slate-600/60 font-mono">
                {fallbackCvssLabel}: {fallbackCvssScore.toFixed(1)}
              </span>
            )}
          </div>

          <div className="flex items-center gap-4 mt-2">
            {!isRejected && (
                <button 
                  onClick={() => setExpanded(!expanded)}
                  className="text-xs font-medium text-slate-400 hover:text-white flex items-center gap-1 transition-colors focus:outline-none"
                >
                  {expanded ? (
                    <>
                      <ChevronUp className="w-3 h-3" /> Hide Affected Versions
                    </>
                  ) : (
                    <>
                      <ChevronDown className="w-3 h-3" /> Show Affected Versions ({configCount})
                    </>
                  )}
                </button>
            )}
            
          </div>
        </div>
      </div>

      {/* Expanded Details - Affected Versions */}
      {expanded && !isRejected && (
        <div className="mt-4 pt-4 border-t border-white/5">
          <h4 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2 flex items-center gap-2">
            <Server className="w-3 h-3" /> Known Affected Configurations
          </h4>
          <div className="bg-slate-950/50 rounded-lg p-3 max-h-60 overflow-y-auto">
             {configCount === 0 ? (
                 <span className="text-xs text-slate-500 italic">No specific configuration data available from non-restricted sources (e.g., cvelistv5, CERT-FR).</span>
             ) : (
                 <div className="grid grid-cols-1 gap-2">
                    {displayedConfig.map((cpe, idx) => (
                        <div key={idx} className="flex items-center gap-2 text-xs text-slate-400 bg-slate-900/80 p-2 rounded border border-white/5" title={cpe}>
                            <Box className="w-3 h-3 text-slate-600 shrink-0" />
                            <span className="font-mono break-all">{cpe}</span>
                        </div>
                    ))}
                    
                    {hasManyConfigs && (
                        <button 
                            onClick={() => setShowAllConfig(!showAllConfig)}
                            className="flex items-center justify-center gap-1 w-full py-2 mt-1 text-xs font-medium text-blue-400 hover:text-blue-300 hover:bg-blue-500/10 rounded transition-colors"
                        >
                            {showAllConfig ? (
                                <>Show Less <ChevronUp className="w-3 h-3" /></>
                            ) : (
                                <>+ {configCount - configLimit} more configurations <ChevronDown className="w-3 h-3" /></>
                            )}
                        </button>
                    )}
                 </div>
             )}
          </div>
        </div>
      )}
    </div>
  );
};

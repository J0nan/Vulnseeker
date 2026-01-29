import React, { useState, useMemo } from 'react';
import { CVE } from '../types';
import { CVESeverityBadge } from './CVESeverityBadge';
import { ChevronDown, ChevronUp, ExternalLink, Calendar, Server, Box, AlertOctagon, Trash2 } from 'lucide-react';

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

  return (
    <div className={`bg-slate-800/50 border border-white/5 rounded-xl p-5 hover:border-blue-500/30 transition-all duration-300 shadow-lg hover:shadow-xl group ${isRejected ? 'opacity-75 grayscale-[0.5] border-red-900/20' : ''}`}>
      <div className="flex items-start gap-4">
        {/* Severity Score Column */}
        <div className="shrink-0 flex flex-col gap-2 items-center">
          <CVESeverityBadge score={cve.cvss} />
          {isRejected && (
            <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-red-900/30 text-red-400 border border-red-800/50">
              <AlertOctagon className="w-3 h-3" /> Rejected
            </span>
          )}
        </div>

        {/* Content Column */}
        <div className="flex-1 min-w-0">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-2">
            <h3 className={`text-lg font-bold font-mono tracking-tight transition-colors ${isRejected ? 'text-slate-400 line-through decoration-red-500/50' : 'text-blue-400 group-hover:text-blue-300'}`}>
              {cve.id}
            </h3>
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
            
            <a 
              href={`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve.id}`} 
              target="_blank" 
              rel="noopener noreferrer"
              className="text-xs font-medium text-slate-400 hover:text-blue-400 flex items-center gap-1 transition-colors ml-auto"
            >
              MITRE <ExternalLink className="w-3 h-3" />
            </a>
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
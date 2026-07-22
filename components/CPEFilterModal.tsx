import React, { useState } from 'react';
import { X, Shield, Box, Layers, CheckCircle } from 'lucide-react';
import { CVE } from '../types';

interface CPEFilterModalProps {
  isOpen: boolean;
  onClose: () => void;
  onApply: (cves: CVE[], cpeString: string) => void;
  vendor: string;
  product: string;
}

export const CPEFilterModal: React.FC<CPEFilterModalProps> = ({ isOpen, onClose, onApply, vendor, product }) => {
  const [version, setVersion] = useState('');
  const [part, setPart] = useState('a');
  
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState('');
  const [pendingResults, setPendingResults] = useState<{ cves: CVE[], cpeString: string } | null>(null);

  if (!isOpen) {
    if (pendingResults) setPendingResults(null);
    return null;
  }

  const handleClose = () => {
    setPendingResults(null);
    setError('');
    onClose();
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!version) {
      setError('Please provide a version.');
      return;
    }

    setIsSearching(true);
    setError('');

    try {
      const safeVendor = encodeURIComponent(vendor.trim().toLowerCase());
      const safeProduct = encodeURIComponent(product.trim().toLowerCase());
      const safeVersion = encodeURIComponent(version.trim().toLowerCase());
      
      const cpeString = `cpe:2.3:${part}:${safeVendor}:${safeProduct}:${safeVersion}:*:*:*:*:*:*:*`;
      
      let allResults: any[] = [];
      let startIndex = 0;
      const RESULTS_PER_PAGE = 2000;
      let totalResults = 1;
      
      while (startIndex < totalResults) {
        const nvdUrl = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${encodeURIComponent(cpeString)}&resultsPerPage=${RESULTS_PER_PAGE}&startIndex=${startIndex}`;
        const proxyUrl = `https://cors.ja1712.workers.dev/?url=${encodeURIComponent(nvdUrl)}`;
        
        if (startIndex > 0) {
          await new Promise(r => setTimeout(r, 6000));
        }

        const res = await fetch(proxyUrl);
        if (!res.ok) {
           throw new Error(`Failed to fetch from NVD: ${res.status}`);
        }
        
        const data = await res.json();
        totalResults = data.totalResults || 0;
        
        if (data.vulnerabilities) {
           allResults = allResults.concat(data.vulnerabilities);
        }
        
        startIndex += RESULTS_PER_PAGE;
      }

      const parsedCves: CVE[] = allResults.map(item => {
        const cve = {
          id: item.cve.id,
          summary: item.cve.descriptions?.find((d: any) => d.lang === 'en')?.value || 'No description available',
          cvss: null as number | null,
          Published: item.cve.published || '',
          Modified: item.cve.lastModified || '',
          vulnerable_configuration: [],
          references: (item.cve.references || []).map((r: any) => r.url),
          vulnStatus: item.cve.vulnStatus,
        } as CVE;

        const metrics = item.cve.metrics;
        if (metrics) {
          if (metrics.cvssMetricV40?.[0]) {
            cve.cvssV40 = metrics.cvssMetricV40[0].cvssData.baseScore;
            cve.cvssVectorV40 = metrics.cvssMetricV40[0].cvssData.vectorString;
          }
          if (metrics.cvssMetricV31?.[0]) {
            cve.cvssV31 = metrics.cvssMetricV31[0].cvssData.baseScore;
            cve.cvssVectorV31 = metrics.cvssMetricV31[0].cvssData.vectorString;
          }
          if (metrics.cvssMetricV30?.[0]) {
            cve.cvssV30 = metrics.cvssMetricV30[0].cvssData.baseScore;
            cve.cvssVectorV30 = metrics.cvssMetricV30[0].cvssData.vectorString;
          }
          if (metrics.cvssMetricV2?.[0]) {
            cve.cvssV20 = metrics.cvssMetricV2[0].cvssData.baseScore;
            cve.cvssVectorV20 = metrics.cvssMetricV2[0].cvssData.vectorString;
          }

          cve.cvss = cve.cvssV40 ?? cve.cvssV31 ?? cve.cvssV30 ?? cve.cvssV20 ?? null;
        }
        
        return cve;
      });

      setPendingResults({ cves: parsedCves, cpeString });
    } catch (err: any) {
      setError(err.message || 'Failed to fetch from NVD.');
    } finally {
      setIsSearching(false);
    }
  };

  const handleApply = () => {
    if (pendingResults) {
      onApply(pendingResults.cves, pendingResults.cpeString);
      handleClose();
    }
  };

  const handleDiscard = () => {
    setPendingResults(null);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm animate-in fade-in duration-200">
      <div className="bg-slate-900 border border-slate-700/50 rounded-2xl shadow-2xl w-full max-w-md overflow-hidden flex flex-col transition-all">
        <div className="px-6 py-4 border-b border-slate-800 flex justify-between items-center bg-slate-900/50">
          <h3 className="text-lg font-semibold text-white flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-400" />
            NVD Version Filter
          </h3>
          <button
            onClick={handleClose}
            className="text-slate-400 hover:text-white transition-colors p-1 rounded-lg hover:bg-slate-800"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {pendingResults ? (
          <div className="p-8 flex flex-col items-center text-center space-y-6 animate-in zoom-in-95">
            <div className="w-16 h-16 rounded-full bg-green-900/30 flex items-center justify-center border border-green-800/50">
              <CheckCircle className="w-8 h-8 text-green-400" />
            </div>
            
            <div className="space-y-2">
              <h4 className="text-xl font-bold text-white">Search Complete</h4>
              <p className="text-slate-300">
                Found <span className="font-bold text-blue-400 text-lg">{pendingResults.cves.length}</span> vulnerabilities affecting version <span className="font-semibold text-white">{version}</span>.
              </p>
            </div>

            <div className="flex w-full gap-3 pt-4">
              <button
                onClick={handleDiscard}
                className="flex-1 bg-slate-800 hover:bg-slate-700 text-white font-medium py-2.5 rounded-lg transition-all border border-slate-700 hover:border-slate-600"
              >
                Discard
              </button>
              <button
                onClick={handleApply}
                className="flex-1 bg-blue-600 hover:bg-blue-500 text-white font-medium py-2.5 rounded-lg transition-all shadow-lg shadow-blue-900/20"
              >
                Accept & Apply
              </button>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSubmit} className="p-6 space-y-5">
            {error && (
              <div className="p-3 rounded-lg bg-red-900/30 border border-red-800/50 text-red-300 text-sm">
                {error}
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Layers className="w-4 h-4 text-slate-400" />
                Component Type
              </label>
              <select
                value={part}
                onChange={(e) => setPart(e.target.value)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all appearance-none"
              >
                <option value="a">Application (a)</option>
                <option value="o">Operating System (o)</option>
                <option value="h">Hardware (h)</option>
              </select>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Box className="w-4 h-4 text-slate-400" />
                {product} Version
              </label>
              <input
                type="text"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="e.g. 1607"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-all"
                required
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isSearching || !version}
                className="w-full bg-blue-600 hover:bg-blue-500 text-white font-medium py-2.5 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2 shadow-lg shadow-blue-900/20"
              >
                {isSearching ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    Searching NVD...
                  </>
                ) : (
                  <>
                    <Shield className="w-4 h-4" />
                    Search NVD
                  </>
                )}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
};

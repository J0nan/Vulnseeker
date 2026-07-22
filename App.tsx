import React, { useState, FormEvent, useMemo, useEffect, useRef, useCallback } from 'react';
import { Header } from './components/Header';
import { CVE, LoadingState, SavedSearch } from './types';
import { searchCVEs, searchVendors, getProductsByVendor, enrichCvssVectorsInBackground } from './services/cveService';
import { CVECard } from './components/CVECard';
import { Autocomplete } from './components/Autocomplete';
import { SavedSearches } from './components/SavedSearches';
import { Search, AlertTriangle, Database, Info, Box, Save, Sparkles, RefreshCw, CheckCircle, Shield } from 'lucide-react';
import { AIFilterModal } from './components/AIFilterModal';
import { CPEFilterModal } from './components/CPEFilterModal';

type CvssSortBasis = 'cvssV40' | 'cvssFallback';

type SeverityCounts = {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
};

type SeverityLevel = keyof SeverityCounts;
type SeverityFilter = SeverityLevel | 'all';

const severityChipConfig: Array<{ level: SeverityLevel; label: string; className: string }> = [
  { level: 'critical', label: 'Critical', className: 'bg-purple-900/30 text-purple-300 border border-purple-800/50' },
  { level: 'high', label: 'High', className: 'bg-red-900/30 text-red-300 border border-red-800/50' },
  { level: 'medium', label: 'Medium', className: 'bg-orange-900/30 text-orange-300 border border-orange-800/50' },
  { level: 'low', label: 'Low', className: 'bg-green-900/30 text-green-300 border border-green-800/50' },
  { level: 'unknown', label: 'Unknown', className: 'bg-slate-700/40 text-slate-300 border border-slate-600/60' }
];

const getCvssFallbackScore = (cve: CVE): number | null => {
  return cve.cvssV31 ?? cve.cvssV30 ?? cve.cvssV20 ?? null;
};

const createSeverityCounts = (): SeverityCounts => ({
  critical: 0,
  high: 0,
  medium: 0,
  low: 0,
  unknown: 0
});

const incrementSeverityCounts = (counts: SeverityCounts, score: number | null | undefined): void => {
  if (score === null || score === undefined) {
    counts.unknown++;
  } else if (score >= 9.0) {
    counts.critical++;
  } else if (score >= 7.0) {
    counts.high++;
  } else if (score >= 4.0) {
    counts.medium++;
  } else {
    counts.low++;
  }
};

const getSeverityLevel = (score: number | null | undefined): SeverityLevel => {
  if (score === null || score === undefined) {
    return 'unknown';
  }

  if (score >= 9.0) {
    return 'critical';
  }

  if (score >= 7.0) {
    return 'high';
  }

  if (score >= 4.0) {
    return 'medium';
  }

  return 'low';
};

function App() {
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [cves, setCves] = useState<CVE[]>([]);
  const [loadingState, setLoadingState] = useState<LoadingState>(LoadingState.IDLE);
  const [errorMsg, setErrorMsg] = useState<string>('');
  const [cvssSortBasis, setCvssSortBasis] = useState<CvssSortBasis>('cvssV40');
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>('all');
  const [isAIFilterOpen, setIsAIFilterOpen] = useState(false);
  const [isCPEFilterOpen, setIsCPEFilterOpen] = useState(false);
  const [activeCPEString, setActiveCPEString] = useState<string | null>(null);

  const [wasEnrichmentCancelledForFilter, setWasEnrichmentCancelledForFilter] = useState(false);
  const [pendingEnrichmentRestart, setPendingEnrichmentRestart] = useState(false);

  // Background enrichment state
  const [enrichmentStatus, setEnrichmentStatus] = useState<{ active: boolean; completed: number; total: number; done: boolean }>({ active: false, completed: 0, total: 0, done: false });
  const enrichmentAbortRef = useRef<AbortController | null>(null);

  // Auto-dismiss the "done" banner after 5 seconds
  useEffect(() => {
    if (enrichmentStatus.done) {
      const timer = setTimeout(() => setEnrichmentStatus(prev => ({ ...prev, done: false })), 5000);
      return () => clearTimeout(timer);
    }
  }, [enrichmentStatus.done]);

  // Cancel enrichment on unmount
  useEffect(() => {
    return () => { enrichmentAbortRef.current?.abort(); };
  }, []);

  const startEnrichment = useCallback((cveList: CVE[]) => {
      const controller = enrichCvssVectorsInBackground(cveList, {
          onProgress: (updatedCves, completed, total) => {
            setCves(prev => [...prev]);
            setEnrichmentStatus({ active: true, completed, total, done: false });
          },
          onComplete: (updatedCves) => {
            setCves(prev => [...prev]);
            setEnrichmentStatus({ active: false, completed: 0, total: 0, done: true });
            enrichmentAbortRef.current = null;
          }
      });
      enrichmentAbortRef.current = controller;
      const needsVector = cveList.filter(cve =>
        cve.vulnStatus !== 'REJECTED' && cve.cvss !== null &&
        !cve.cvssVectorV40 && !cve.cvssVectorV31 && !cve.cvssVectorV30 && !cve.cvssVectorV20
      );
      if (needsVector.length > 0) {
        setEnrichmentStatus({ active: true, completed: 0, total: needsVector.length, done: false });
      }
  }, []);

  const executeFilterAction = (applyFilter: () => void, isAsyncModal: boolean = false) => {
      if (enrichmentStatus.active) {
          if (window.confirm("The background task of Fetching CVSS vectors from NVD is running. Do you want it to stop?")) {
              enrichmentAbortRef.current?.abort();
              enrichmentAbortRef.current = null;
              setEnrichmentStatus(prev => ({ ...prev, active: false }));
              applyFilter();
              if (isAsyncModal) {
                  setWasEnrichmentCancelledForFilter(true);
              } else {
                  setPendingEnrichmentRestart(true);
              }
          }
      } else {
          applyFilter();
      }
  };
  
  // State for product autocomplete
  const [vendorProducts, setVendorProducts] = useState<string[]>([]);
  const [isFetchingProducts, setIsFetchingProducts] = useState(false);

  // Saved Searches State
  const [savedSearches, setSavedSearches] = useState<SavedSearch[]>([]);
  useEffect(() => {
    try {
      const saved = localStorage.getItem('vulnseeker_saved_searches');
      if (saved) {
        setSavedSearches(JSON.parse(saved));
      }
    } catch {
      // ignore
    }
  }, []);


  // Persist saved searches
  useEffect(() => {
    localStorage.setItem('vulnseeker_saved_searches', JSON.stringify(savedSearches));
  }, [savedSearches]);

  const stats = useMemo(() => {
    const cvssV40 = createSeverityCounts();
    const cvssFallback = createSeverityCounts();

    cves.forEach(cve => {
      incrementSeverityCounts(cvssV40, cve.cvssV40);
      incrementSeverityCounts(cvssFallback, getCvssFallbackScore(cve));
    });

    return {
      cvssV40,
      cvssFallback
    };
  }, [cves]);

  const filteredSortedCves = useMemo(() => {
    const getSelectedScore = (cve: CVE) => {
      return cvssSortBasis === 'cvssV40' ? (cve.cvssV40 ?? null) : getCvssFallbackScore(cve);
    };

    return cves
      .filter((cve) => {
        if (severityFilter === 'all') {
          return true;
        }

        return getSeverityLevel(getSelectedScore(cve)) === severityFilter;
      })
      .sort((a, b) => {
        const scoreA = getSelectedScore(a) ?? -1;
        const scoreB = getSelectedScore(b) ?? -1;
        return scoreB - scoreA;
      });
  }, [cves, cvssSortBasis, severityFilter]);

  useEffect(() => {
    if (pendingEnrichmentRestart) {
       startEnrichment(filteredSortedCves);
       setPendingEnrichmentRestart(false);
    }
  }, [filteredSortedCves, pendingEnrichmentRestart, startEnrichment]);

  const handleSeverityChipClick = (group: CvssSortBasis, severity: SeverityLevel) => {
    executeFilterAction(() => {
      setCvssSortBasis(group);
      setSeverityFilter((prevFilter) => {
        if (cvssSortBasis === group && prevFilter === severity) {
          return 'all';
        }

        return severity;
      });
    }, false);
  };

  const renderSeverityChips = (group: CvssSortBasis, counts: SeverityCounts) => {
    return severityChipConfig.map(({ level, label, className }) => {
      const count = counts[level];
      if (count === 0) {
        return null;
      }

      const isActive = cvssSortBasis === group && severityFilter === level;
      const isFilterActive = severityFilter !== 'all';
      const chipVisualClass = isActive
        ? 'ring-2 ring-blue-400/80 shadow-md shadow-blue-500/20'
        : isFilterActive
          ? 'opacity-45 grayscale-[0.35] saturate-50 hover:opacity-60'
          : cvssSortBasis === group
            ? 'hover:brightness-110'
            : 'opacity-80 hover:opacity-100';

      return (
        <button
          key={`${group}-${level}`}
          type="button"
          onClick={() => handleSeverityChipClick(group, level)}
          aria-pressed={isActive}
          className={`px-2 py-1 rounded text-xs font-semibold transition-all ${className} ${chipVisualClass}`}
          title={isActive ? `Clear ${label} filter` : `Filter by ${label} (${group === 'cvssV40' ? 'CVSS v4.0' : 'fallback'})`}
        >
          {count} {label}
        </button>
      );
    });
  };

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault();
    if (!vendor || !product) return;

    // Cancel any in-flight enrichment from a previous search
    enrichmentAbortRef.current?.abort();
    enrichmentAbortRef.current = null;
    setEnrichmentStatus({ active: false, completed: 0, total: 0, done: false });

    setLoadingState(LoadingState.LOADING);
    setErrorMsg('');
    setCves([]);
    setSeverityFilter('all');
    setActiveCPEString(null);

    try {
      const results = await searchCVEs(vendor, product);
      if (results.length === 0) {
        setLoadingState(LoadingState.EMPTY);
      } else {
        setCves(results);
        setLoadingState(LoadingState.SUCCESS);

        // Kick off background NVD vector enrichment
        startEnrichment(results);
      }
    } catch (err) {
      setLoadingState(LoadingState.ERROR);
      setErrorMsg('Failed to fetch data. Please check your connection or try a different query.');
    }
  };

  const handleDelete = (id: string) => {
    setCves((prevCves) => prevCves.filter((cve) => cve.id !== id));
  };

  const handleSaveSearch = () => {
    if (cves.length === 0) return;
    
    // Create a unique ID and a default label
    const label = `${vendor} - ${product}`;
    const newSave: SavedSearch = {
        id: Date.now().toString() + Math.random().toString(36).substring(2),
        label,
        timestamp: Date.now(),
        vendor,
        product,
        cves: [...cves] // Save a copy of the current state
    };

    setSavedSearches(prev => [newSave, ...prev]);
  };

  const handleLoadSearch = (search: SavedSearch) => {
    setVendor(search.vendor);
    setProduct(search.product);
    setCves(search.cves);
    setLoadingState(LoadingState.SUCCESS);
    setErrorMsg('');
    setSeverityFilter('all');
    
    // Optionally fetch products for the loaded vendor to populate the dropdown
    handleVendorSelect(search.vendor);
    
    // Scroll to results
    window.scrollTo({ top: 300, behavior: 'smooth' });
  };

  const handleDeleteSavedSearch = (id: string) => {
    setSavedSearches(prev => prev.filter(s => s.id !== id));
  };

  const handleClearAllSavedSearches = () => {
    setSavedSearches([]);
  };

  const handleRenameSavedSearch = (id: string, newLabel: string) => {
    setSavedSearches(prev => prev.map(s => s.id === id ? { ...s, label: newLabel } : s));
  };

  const handleImportSavedSearches = (importedSearches: SavedSearch[]) => {
    // Generate new IDs for imported items to avoid collisions with existing ones
    const newItems = importedSearches.map(item => ({
        ...item,
        id: Date.now().toString() + Math.random().toString(36).substring(2)
    }));
    
    setSavedSearches(prev => [...newItems, ...prev]);
  };
  
  const handleVendorSelect = async (selectedVendor: string) => {
      if (!selectedVendor) return;
      setIsFetchingProducts(true);
      try {
          const products = await getProductsByVendor(selectedVendor);
          setVendorProducts(products);
          setProduct('');
      } catch (e) {
          console.error("Failed to load products", e);
      } finally {
          setIsFetchingProducts(false);
      }
  };

  const handleAIFilterApply = (filteredCves: CVE[]) => {
      setCves(filteredCves);
      setActiveCPEString(null);
      if (wasEnrichmentCancelledForFilter) {
          setPendingEnrichmentRestart(true);
          setWasEnrichmentCancelledForFilter(false);
      }
  };

  const handleCPEFilterApply = (filteredCves: CVE[], cpeString: string) => {
      setCves(filteredCves);
      setActiveCPEString(cpeString);
      if (wasEnrichmentCancelledForFilter) {
          setPendingEnrichmentRestart(true);
          setWasEnrichmentCancelledForFilter(false);
      }
  };

  return (
    <div className="min-h-screen flex flex-col font-sans bg-background text-slate-200">
      <Header />

      <main className="flex-1 w-full max-w-7xl mx-auto px-4 py-8 md:px-8">
        
        {/* Search Section */}
        <section className="max-w-3xl mx-auto mb-12 text-center">
          <h2 className="text-3xl md:text-4xl font-bold text-white mb-4">
            Identify Vulnerabilities
          </h2>
          <p className="text-slate-400 mb-8 text-lg">
            Search the global database for reported security flaws by vendor and product name.
          </p>
          
          <form onSubmit={handleSearch} className="bg-surface p-2 rounded-2xl shadow-2xl border border-white/5 flex flex-col md:flex-row gap-2 relative z-20">
            <Autocomplete
                value={vendor}
                onChange={setVendor}
                onSelect={handleVendorSelect}
                fetchSuggestions={searchVendors}
                placeholder="Vendor (e.g. Microsoft)"
                icon={<Database className="h-5 w-5" />}
                required
            />
            
            <div className="w-px h-10 bg-white/10 self-center hidden md:block"></div>
            
            <Autocomplete
                value={product}
                onChange={setProduct}
                staticSuggestions={vendorProducts}
                placeholder={isFetchingProducts ? "Loading products..." : "Product (e.g. Office)"}
                icon={<Box className="h-5 w-5" />}
                required
                disabled={isFetchingProducts}
            />

            <button
              type="submit"
              disabled={loadingState === LoadingState.LOADING || !vendor || !product}
              className="bg-blue-600 hover:bg-blue-500 text-white font-semibold py-3 px-8 rounded-xl transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 shadow-lg shadow-blue-600/20"
            >
              {loadingState === LoadingState.LOADING ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                  Searching...
                </>
              ) : (
                <>
                  <Search className="w-5 h-5" />
                  Search
                </>
              )}
            </button>
          </form>
          
          <div className="mt-4 flex gap-4 justify-center text-xs text-slate-500">
             <span className="flex items-center gap-1"><Info className="w-3 h-3"/> Try "Apple" & "iPhone OS"</span>
             <span className="flex items-center gap-1"><Info className="w-3 h-3"/> Try "Apache" & "Log4j"</span>
          </div>
        </section>

        {/* Saved Searches Section */}
        <SavedSearches 
            searches={savedSearches} 
            onLoad={handleLoadSearch}
            onDelete={handleDeleteSavedSearch}
            onRename={handleRenameSavedSearch}
            onImport={handleImportSavedSearches}
            onClearAll={handleClearAllSavedSearches}
        />

        {/* Results Section */}
        <div className="space-y-6 z-10 relative">
          {loadingState === LoadingState.IDLE && savedSearches.length === 0 && (
            <div className="text-center py-20 opacity-50">
              <div className="inline-block p-6 rounded-full bg-slate-800/50 mb-4">
                 <Search className="w-12 h-12 text-slate-600" />
              </div>
              <p className="text-slate-500 text-lg">Enter a vendor and product to identify risks.</p>
            </div>
          )}

          {loadingState === LoadingState.EMPTY && (
            <div className="text-center py-20 bg-slate-800/20 rounded-2xl border border-dashed border-slate-700">
              <div className="inline-block p-4 rounded-full bg-slate-800 mb-4">
                 <AlertTriangle className="w-8 h-8 text-yellow-500" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">No Vulnerabilities Found</h3>
              <p className="text-slate-400">Great news! We couldn't find any CVEs for "{vendor} {product}".</p>
              <p className="text-slate-500 text-sm mt-2">Check your spelling or try different keywords.</p>
            </div>
          )}

          {loadingState === LoadingState.ERROR && (
            <div className="text-center py-20">
              <div className="inline-block p-4 rounded-full bg-red-900/20 mb-4">
                 <AlertTriangle className="w-8 h-8 text-red-500" />
              </div>
              <h3 className="text-xl font-semibold text-white mb-2">Search Failed</h3>
              <p className="text-red-300">{errorMsg}</p>
            </div>
          )}

          {loadingState === LoadingState.SUCCESS && (
            <>
              <div className="mb-6 space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                  <h3 className="text-xl font-bold text-white flex items-center gap-2">
                    Results
                    <span className="px-2.5 py-0.5 rounded-full bg-blue-500/10 text-blue-400 text-sm font-mono">
                      {severityFilter === 'all' ? `${cves.length} found` : `${filteredSortedCves.length}/${cves.length} shown`}
                    </span>
                    {activeCPEString && (
                      <a 
                        href={`https://nvd.nist.gov/vuln/search#/nvd/home?cpeFilterMode=cpe&cpeName=${encodeURIComponent(activeCPEString)}&resultType=records`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="ml-4 text-xs font-medium text-blue-400 hover:text-blue-300 flex items-center gap-1 hover:underline"
                        title="View on NIST National Vulnerability Database"
                      >
                        <Shield className="w-3.5 h-3.5" />
                        View in NIST NVD
                      </a>
                    )}
                  </h3>

                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => executeFilterAction(() => setIsAIFilterOpen(true), true)}
                      className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-purple-600 hover:bg-purple-500 rounded-lg border border-purple-500 hover:border-purple-400 transition-all shadow-sm shadow-purple-900/50"
                      title="Filter results for a specific version using AI"
                    >
                      <Sparkles className="w-4 h-4" />
                      Filter Version (AI)
                    </button>
                    <button
                      onClick={() => executeFilterAction(() => setIsCPEFilterOpen(true), true)}
                      className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-white bg-blue-600 hover:bg-blue-500 rounded-lg border border-blue-500 hover:border-blue-400 transition-all shadow-sm shadow-blue-900/50"
                      title="Filter results for a specific version using NVD API"
                    >
                      <Shield className="w-4 h-4" />
                      Filter Version (NVD)
                    </button>
                    <button
                      onClick={handleSaveSearch}
                      className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-slate-300 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg border border-slate-700 hover:border-slate-600 transition-all shadow-sm"
                      title="Save this search snapshot"
                    >
                      <Save className="w-4 h-4" />
                      Save Snapshot
                    </button>
                  </div>
                </div>

                <div className="flex flex-col xl:flex-row gap-4 xl:items-center xl:justify-between">
                  <div className="rounded-xl border border-slate-700/70 bg-slate-900/40 p-3">
                    <div className="mb-3 flex justify-end">
                      <button
                        type="button"
                        onClick={() => executeFilterAction(() => setSeverityFilter('all'), false)}
                        disabled={severityFilter === 'all'}
                        className="px-3 py-1.5 rounded text-xs font-semibold border border-slate-700 bg-slate-900 text-slate-300 hover:bg-slate-800 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                        title="Clear severity filter"
                      >
                        All severities
                      </button>
                    </div>

                    <div className="flex flex-col lg:flex-row gap-3 lg:items-stretch">
                      <div className={`flex flex-col gap-2 rounded-lg border p-2 ${cvssSortBasis === 'cvssV40' ? 'border-blue-500/60 bg-blue-950/30' : 'border-slate-700/70 bg-slate-900/60'}`}>
                        <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">CVSS v4.0</span>
                        <div className="flex flex-wrap gap-2">
                          {renderSeverityChips('cvssV40', stats.cvssV40)}
                        </div>
                      </div>

                      <div className="hidden lg:block w-px bg-slate-700/80" />

                      <div className={`flex flex-col gap-2 rounded-lg border p-2 ${cvssSortBasis === 'cvssFallback' ? 'border-blue-500/60 bg-blue-950/30' : 'border-slate-700/70 bg-slate-900/60'}`}>
                        <span className="text-[10px] uppercase tracking-wider font-semibold text-slate-400">Fallback (3.1→3.0→2.0)</span>
                        <div className="flex flex-wrap gap-2">
                          {renderSeverityChips('cvssFallback', stats.cvssFallback)}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-2">
                    <label className="flex items-center gap-2 text-xs text-slate-400">
                      <span className="whitespace-nowrap">Sort by score:</span>
                      <select
                        value={cvssSortBasis}
                        onChange={(e) => setCvssSortBasis(e.target.value as CvssSortBasis)}
                        className="rounded border border-slate-700 bg-slate-900 px-2 py-1 text-xs text-slate-200 focus:border-blue-500 focus:outline-none"
                      >
                        <option value="cvssV40">CVSS v4.0</option>
                        <option value="cvssFallback">CVSS 3.x fallback (3.1→3.0→2.0)</option>
                      </select>
                    </label>
                  </div>
                </div>
              </div>
              
              {/* Background enrichment banner */}
              {enrichmentStatus.active && (
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-blue-950/40 border border-blue-800/40 text-blue-300 text-sm mb-2 animate-in">
                  <RefreshCw className="w-4 h-4 animate-spin shrink-0" />
                  <span>
                    Fetching CVSS vectors from NVD… <span className="font-mono text-blue-400">{enrichmentStatus.completed}/{enrichmentStatus.total}</span>
                  </span>
                  <div className="flex-1 h-1.5 bg-blue-900/50 rounded-full overflow-hidden ml-2">
                    <div
                      className="h-full bg-blue-500 rounded-full transition-all duration-500 ease-out"
                      style={{ width: `${enrichmentStatus.total > 0 ? (enrichmentStatus.completed / enrichmentStatus.total) * 100 : 0}%` }}
                    />
                  </div>
                </div>
              )}
              {enrichmentStatus.done && (
                <div className="flex items-center gap-3 px-4 py-3 rounded-xl bg-green-950/40 border border-green-800/40 text-green-300 text-sm mb-2">
                  <CheckCircle className="w-4 h-4 shrink-0" />
                  <span>CVSS vectors enriched successfully.</span>
                </div>
              )}

              <div className="grid grid-cols-1 gap-4">
                {filteredSortedCves.map((cve) => (
                  <CVECard key={cve.id} cve={cve} onDelete={() => handleDelete(cve.id)} />
                ))}
              </div>
            </>
          )}
        </div>

        <AIFilterModal 
          isOpen={isAIFilterOpen} 
          onClose={() => {
              setIsAIFilterOpen(false);
              if (wasEnrichmentCancelledForFilter) {
                  setPendingEnrichmentRestart(true);
                  setWasEnrichmentCancelledForFilter(false);
              }
          }} 
          onApply={handleAIFilterApply} 
          productName={product} 
          cves={cves}
        />

        <CPEFilterModal
          isOpen={isCPEFilterOpen}
          onClose={() => {
              setIsCPEFilterOpen(false);
              if (wasEnrichmentCancelledForFilter) {
                  setPendingEnrichmentRestart(true);
                  setWasEnrichmentCancelledForFilter(false);
              }
          }}
          onApply={handleCPEFilterApply}
          vendor={vendor}
          product={product}
        />
      </main>
      
      <footer className="py-8 text-center text-slate-600 text-sm">
        <p>&copy; {new Date().getFullYear()} VulnSeeker. Data provided by CIRCL.</p>
      </footer>
    </div>
  );
}

export default App;

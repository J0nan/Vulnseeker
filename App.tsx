import React, { useState, FormEvent, useMemo, useEffect } from 'react';
import { Header } from './components/Header';
import { CVE, LoadingState, SavedSearch } from './types';
import { searchCVEs, searchVendors, getProductsByVendor } from './services/cveService';
import { CVECard } from './components/CVECard';
import { Autocomplete } from './components/Autocomplete';
import { SavedSearches } from './components/SavedSearches';
import { Search, AlertTriangle, Database, Info, Box, Save } from 'lucide-react';

function App() {
  const [vendor, setVendor] = useState('');
  const [product, setProduct] = useState('');
  const [cves, setCves] = useState<CVE[]>([]);
  const [loadingState, setLoadingState] = useState<LoadingState>(LoadingState.IDLE);
  const [errorMsg, setErrorMsg] = useState<string>('');
  
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
    const counts = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    cves.forEach(cve => {
      const score = cve.cvss;
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
    });
    return counts;
  }, [cves]);

  const handleSearch = async (e: FormEvent) => {
    e.preventDefault();
    if (!vendor || !product) return;

    setLoadingState(LoadingState.LOADING);
    setErrorMsg('');
    setCves([]);

    try {
      const results = await searchCVEs(vendor, product);
      if (results.length === 0) {
        setLoadingState(LoadingState.EMPTY);
      } else {
        // Sort by CVSS score descending (high to low), putting null/undefined at the end
        const sortedResults = results.sort((a, b) => {
          const scoreA = a.cvss ?? -1;
          const scoreB = b.cvss ?? -1;
          return scoreB - scoreA;
        });
        setCves(sortedResults);
        setLoadingState(LoadingState.SUCCESS);
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
  
  // When a vendor is selected, fetch products for that vendor
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
              <div className="flex flex-col md:flex-row md:items-center justify-between mb-6 gap-4">
                <h3 className="text-xl font-bold text-white flex items-center gap-2">
                  Results 
                  <span className="px-2.5 py-0.5 rounded-full bg-blue-500/10 text-blue-400 text-sm font-mono">
                    {cves.length} found
                  </span>
                </h3>
                
                <div className="flex flex-col md:flex-row gap-4 md:items-center">
                    <div className="flex flex-wrap gap-2">
                        {stats.critical > 0 && (
                            <span className="px-2 py-1 rounded text-xs font-semibold bg-purple-900/30 text-purple-300 border border-purple-800/50">
                                {stats.critical} Critical
                            </span>
                        )}
                        {stats.high > 0 && (
                            <span className="px-2 py-1 rounded text-xs font-semibold bg-red-900/30 text-red-300 border border-red-800/50">
                                {stats.high} High
                            </span>
                        )}
                        {stats.medium > 0 && (
                            <span className="px-2 py-1 rounded text-xs font-semibold bg-orange-900/30 text-orange-300 border border-orange-800/50">
                                {stats.medium} Medium
                            </span>
                        )}
                        {stats.low > 0 && (
                            <span className="px-2 py-1 rounded text-xs font-semibold bg-green-900/30 text-green-300 border border-green-800/50">
                                {stats.low} Low
                            </span>
                        )}
                    </div>
                    
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
              
              <div className="grid grid-cols-1 gap-4">
                {cves.map((cve) => (
                  <CVECard key={cve.id} cve={cve} onDelete={() => handleDelete(cve.id)} />
                ))}
              </div>
            </>
          )}
        </div>
      </main>
      
      <footer className="py-8 text-center text-slate-600 text-sm">
        <p>&copy; {new Date().getFullYear()} VulnSeeker. Data provided by CIRCL.</p>
      </footer>
    </div>
  );
}

export default App;
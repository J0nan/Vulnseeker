import React, { useState, useEffect } from 'react';
import { X, Sparkles, Key, Box, Cpu, Settings, CheckCircle } from 'lucide-react';
import { AIProvider, fetchAvailableModels, filterCVEsWithAI } from '../services/aiService';
import { CVE } from '../types';

interface AIFilterModalProps {
  isOpen: boolean;
  onClose: () => void;
  onApply: (cves: CVE[]) => void;
  productName: string;
  cves: CVE[];
}

const PROVIDER_OPTIONS: { id: AIProvider; label: string }[] = [
  { id: 'gemini', label: 'Google Gemini' },
  { id: 'chatgpt', label: 'ChatGPT (OpenAI)' },
  { id: 'claude', label: 'Claude (Anthropic)' },
  { id: 'custom', label: 'Custom (OpenAI Compatible)' }
];

const DEFAULT_MODELS: Record<AIProvider, string[]> = {
  gemini: ['gemini-1.5-flash', 'gemini-1.5-pro', 'gemini-2.5-flash', 'gemma-2-27b-it'],
  chatgpt: ['gpt-4o', 'gpt-4o-mini', 'gpt-3.5-turbo'],
  claude: ['claude-3-5-sonnet-20240620', 'claude-3-haiku-20240307', 'claude-3-opus-20240229'],
  custom: ['llama3', 'mistral', 'mixtral']
};

export const AIFilterModal: React.FC<AIFilterModalProps> = ({ isOpen, onClose, onApply, productName, cves }) => {
  const [provider, setProvider] = useState<AIProvider>('gemini');
  const [apiKey, setApiKey] = useState('');
  const [saveApiKey, setSaveApiKey] = useState(false);
  
  const [availableModels, setAvailableModels] = useState<string[]>([]);
  const [selectedModel, setSelectedModel] = useState('');
  const [isCustomModel, setIsCustomModel] = useState(false);
  const [isLoadingModels, setIsLoadingModels] = useState(false);
  
  const [version, setVersion] = useState('');
  const [customBaseUrl, setCustomBaseUrl] = useState('http://localhost:11434/v1');
  
  const [isFiltering, setIsFiltering] = useState(false);
  const [error, setError] = useState('');
  const [pendingResults, setPendingResults] = useState<CVE[] | null>(null);

  // Load saved key when provider changes or modal opens
  useEffect(() => {
    if (isOpen) {
      const savedKey = localStorage.getItem(`vulnseeker_${provider}_key`);
      if (savedKey) {
        setApiKey(savedKey);
        setSaveApiKey(true);
      } else {
        setApiKey('');
        setSaveApiKey(false);
      }
      
      setError('');
    }
  }, [isOpen, provider]);

  // Fetch models dynamically
  useEffect(() => {
    if (!isOpen || pendingResults) return; // Don't fetch if confirming results
    
    let isMounted = true;
    
    const getModels = async () => {
      // Don't try fetching if we need a key and don't have one (custom doesn't strictly need one)
      if (provider !== 'custom' && (!apiKey || apiKey.length < 5)) {
        setAvailableModels(DEFAULT_MODELS[provider]);
        if (!isCustomModel) setSelectedModel(DEFAULT_MODELS[provider][0]);
        return;
      }
      
      setIsLoadingModels(true);
      try {
        const fetched = await fetchAvailableModels(provider, apiKey, customBaseUrl);
        if (isMounted) {
          if (fetched && fetched.length > 0) {
            setAvailableModels(fetched);
            // Default to the first fetched model if not using custom text input
            if (!isCustomModel) {
               // Try to smartly select a standard one, otherwise first
               const standardFound = fetched.find(m => m.includes('1.5-flash') || m.includes('4o-mini') || m.includes('sonnet'));
               setSelectedModel(standardFound || fetched[0]);
            }
          } else {
            // Fallback to defaults if fetch returned empty
            setAvailableModels(DEFAULT_MODELS[provider]);
            if (!isCustomModel) setSelectedModel(DEFAULT_MODELS[provider][0]);
          }
        }
      } catch (err) {
        if (isMounted) {
          console.warn("Failed to fetch models, falling back to defaults/manual input", err);
          // If fetch fails (rate limits, etc), show defaults but also switch to custom so they aren't blocked
          setAvailableModels(DEFAULT_MODELS[provider]);
          setIsCustomModel(true);
          if (!selectedModel) setSelectedModel(DEFAULT_MODELS[provider][0]);
        }
      } finally {
        if (isMounted) setIsLoadingModels(false);
      }
    };

    const timeoutId = setTimeout(() => {
      getModels();
    }, 500);

    return () => {
      isMounted = false;
      clearTimeout(timeoutId);
    };
  }, [provider, apiKey, customBaseUrl, isOpen, isCustomModel, pendingResults]);

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
    if ((provider !== 'custom' && !apiKey) || !selectedModel || !version) {
      setError('Please fill in all required fields.');
      return;
    }

    if (saveApiKey) {
      localStorage.setItem(`vulnseeker_${provider}_key`, apiKey);
    } else {
      localStorage.removeItem(`vulnseeker_${provider}_key`);
    }

    setIsFiltering(true);
    setError('');

    try {
      const results = await filterCVEsWithAI(provider, apiKey, selectedModel, cves, productName, version, customBaseUrl);
      setPendingResults(results);
    } catch (err: any) {
      setError(err.message || 'Failed to filter using AI.');
    } finally {
      setIsFiltering(false);
    }
  };

  const handleApply = () => {
    if (pendingResults) {
      onApply(pendingResults);
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
            <Sparkles className="w-5 h-5 text-purple-400" />
            AI Version Filter
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
              <h4 className="text-xl font-bold text-white">Filtering Complete</h4>
              <p className="text-slate-300">
                The AI has processed the data and identified <span className="font-bold text-purple-400 text-lg">{pendingResults.length}</span> vulnerabilities affecting version <span className="font-semibold text-white">{version}</span>.
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
                className="flex-1 bg-purple-600 hover:bg-purple-500 text-white font-medium py-2.5 rounded-lg transition-all shadow-lg shadow-purple-900/20"
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
                <Cpu className="w-4 h-4 text-slate-400" />
                AI Provider
              </label>
              <select
                value={provider}
                onChange={(e) => setProvider(e.target.value as AIProvider)}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all appearance-none"
              >
                {PROVIDER_OPTIONS.map(opt => (
                  <option key={opt.id} value={opt.id}>{opt.label}</option>
                ))}
              </select>
            </div>

            {provider === 'custom' && (
              <div className="space-y-1.5 animate-in fade-in slide-in-from-top-2">
                <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                  <Settings className="w-4 h-4 text-slate-400" />
                  Base URL
                </label>
                <input
                  type="text"
                  value={customBaseUrl}
                  onChange={(e) => setCustomBaseUrl(e.target.value)}
                  placeholder="http://localhost:11434/v1"
                  className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all"
                  required={provider === 'custom'}
                />
              </div>
            )}

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Key className="w-4 h-4 text-slate-400" />
                API Key {provider === 'custom' && <span className="text-slate-500 text-xs">(Optional)</span>}
              </label>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder={provider === 'custom' ? "Leave empty if local" : "Enter API Key..."}
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all"
                required={provider !== 'custom'}
              />
              <label className="flex items-center gap-2 mt-2 cursor-pointer w-max">
                <input
                  type="checkbox"
                  checked={saveApiKey}
                  onChange={(e) => setSaveApiKey(e.target.checked)}
                  className="rounded border-slate-700 bg-slate-950 text-purple-500 focus:ring-purple-500/50"
                />
                <span className="text-xs text-slate-400 select-none">Save API Key locally</span>
              </label>
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2 justify-between">
                <span className="flex items-center gap-2">
                  <Cpu className="w-4 h-4 text-slate-400" />
                  Model
                </span>
                <button
                  type="button"
                  onClick={() => {
                     setIsCustomModel(!isCustomModel);
                     if (!isCustomModel) setSelectedModel(selectedModel || DEFAULT_MODELS[provider][0]);
                  }}
                  className="text-xs text-purple-400 hover:text-purple-300"
                >
                  {isCustomModel ? 'Select from list' : 'Enter custom name'}
                </button>
              </label>
              
              {isCustomModel ? (
                 <input
                   type="text"
                   value={selectedModel}
                   onChange={(e) => setSelectedModel(e.target.value)}
                   placeholder={`e.g. ${DEFAULT_MODELS[provider][0]}`}
                   className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all animate-in fade-in"
                   required
                 />
              ) : (
                 <div className="relative animate-in fade-in">
                    <select
                      value={selectedModel}
                      onChange={(e) => setSelectedModel(e.target.value)}
                      disabled={isLoadingModels}
                      className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all appearance-none disabled:opacity-50"
                      required
                    >
                      {availableModels.map((model) => (
                        <option key={model} value={model}>
                          {model}
                        </option>
                      ))}
                    </select>
                    {isLoadingModels && (
                      <div className="absolute right-3 top-3 w-4 h-4 border-2 border-purple-500/30 border-t-purple-500 rounded-full animate-spin"></div>
                    )}
                 </div>
              )}
            </div>

            <div className="space-y-1.5">
              <label className="text-sm font-medium text-slate-300 flex items-center gap-2">
                <Box className="w-4 h-4 text-slate-400" />
                {productName} Version
              </label>
              <input
                type="text"
                value={version}
                onChange={(e) => setVersion(e.target.value)}
                placeholder="e.g. 2.4.65"
                className="w-full bg-slate-950 border border-slate-700 rounded-lg px-4 py-2.5 text-slate-200 placeholder-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50 focus:border-purple-500/50 transition-all"
                required
              />
            </div>

            <div className="pt-2">
              <button
                type="submit"
                disabled={isFiltering || isLoadingModels || (provider !== 'custom' && !apiKey) || !selectedModel || !version}
                className="w-full bg-purple-600 hover:bg-purple-500 text-white font-medium py-2.5 rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex justify-center items-center gap-2 shadow-lg shadow-purple-900/20"
              >
                {isFiltering ? (
                  <>
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin"></div>
                    Filtering via AI...
                  </>
                ) : (
                  <>
                    <Sparkles className="w-4 h-4" />
                    Filter Results
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

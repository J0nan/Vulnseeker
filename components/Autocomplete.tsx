import React, { useState, useEffect, useRef, ReactNode } from 'react';
import { Loader2 } from 'lucide-react';

interface AutocompleteProps {
  value: string;
  onChange: (value: string) => void;
  onSelect?: (value: string) => void;
  placeholder?: string;
  icon?: ReactNode;
  fetchSuggestions?: (query: string) => Promise<string[]>;
  staticSuggestions?: string[];
  disabled?: boolean;
  required?: boolean;
}

export const Autocomplete: React.FC<AutocompleteProps> = ({
  value,
  onChange,
  onSelect,
  placeholder,
  icon,
  fetchSuggestions,
  staticSuggestions,
  disabled,
  required
}) => {
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const [loading, setLoading] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(-1);
  const wrapperRef = useRef<HTMLDivElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  
  // Track the last request query to prevent race conditions
  const lastRequestQueryRef = useRef<string>('');

  useEffect(() => {
    const handleClickOutside = (event: MouseEvent) => {
      if (wrapperRef.current && !wrapperRef.current.contains(event.target as Node)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  // Effect to update suggestions when staticSuggestions changes (e.g. after API load)
  useEffect(() => {
    if (staticSuggestions) {
        // If the user is interacting or has a value, update the list
        if (showSuggestions || value) {
            updateSuggestions(value);
        }
    }
  }, [staticSuggestions]);

  const updateSuggestions = async (query: string) => {
      // Don't fetch if query is too short and we don't have static suggestions
      if (!query && !staticSuggestions) {
          setSuggestions([]);
          return;
      }

      lastRequestQueryRef.current = query;

      if (fetchSuggestions && query.length >= 2) {
          setLoading(true);
          try {
              const results = await fetchSuggestions(query);
              // Only update if this response corresponds to the latest query
              if (lastRequestQueryRef.current === query) {
                  setSuggestions(results);
              }
          } catch (e) {
              if (lastRequestQueryRef.current === query) {
                  setSuggestions([]);
              }
          } finally {
              if (lastRequestQueryRef.current === query) {
                  setLoading(false);
              }
          }
      } else if (staticSuggestions) {
          const lowerQuery = query.toLowerCase();
          const filtered = staticSuggestions.filter(item => 
              item.toLowerCase().includes(lowerQuery)
          );
          setSuggestions(filtered);
      } else {
        setSuggestions([]);
      }
  };

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
      const newValue = e.target.value;
      onChange(newValue);
      setShowSuggestions(true);
      setSelectedIndex(-1);

      if (debounceRef.current) clearTimeout(debounceRef.current);

      debounceRef.current = setTimeout(() => {
          updateSuggestions(newValue);
      }, 300);
  };

  const handleSelect = (item: string) => {
      onChange(item);
      if (onSelect) onSelect(item);
      setShowSuggestions(false);
      setSelectedIndex(-1);
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
      if (!showSuggestions || suggestions.length === 0) return;
      
      if (e.key === 'ArrowDown') {
          e.preventDefault();
          setSelectedIndex(prev => (prev < suggestions.length - 1 ? prev + 1 : prev));
          // Scroll into view logic could be added here
      } else if (e.key === 'ArrowUp') {
          e.preventDefault();
          setSelectedIndex(prev => (prev > 0 ? prev - 1 : prev));
      } else if (e.key === 'Enter') {
          if (selectedIndex >= 0 && selectedIndex < suggestions.length) {
              e.preventDefault();
              handleSelect(suggestions[selectedIndex]);
          }
      } else if (e.key === 'Escape') {
          setShowSuggestions(false);
      }
  };
  
  const handleFocus = () => {
      if (!disabled) {
          setShowSuggestions(true);
          // If we have static suggestions, show them immediately. 
          // If server fetch, only if we have a value to save API calls
          if (staticSuggestions || (fetchSuggestions && value.length >= 2)) {
            updateSuggestions(value); 
          }
      }
  };

  return (
      <div className="relative group flex-1" ref={wrapperRef}>
          <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none z-10 text-slate-500 group-focus-within:text-blue-400 transition-colors">
              {loading ? <Loader2 className="h-5 w-5 animate-spin text-blue-400" /> : icon}
          </div>
          <input
              type="text"
              value={value}
              onChange={handleInputChange}
              onFocus={handleFocus}
              onKeyDown={handleKeyDown}
              placeholder={placeholder}
              disabled={disabled}
              required={required}
              className="block w-full pl-10 pr-3 py-4 bg-transparent border border-transparent rounded-xl text-white placeholder-slate-500 focus:outline-none focus:bg-slate-900/50 focus:border-blue-500/50 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              autoComplete="off"
          />
          
          {showSuggestions && suggestions.length > 0 && (
              <div className="absolute z-50 w-full mt-1 bg-slate-900 border border-slate-700 rounded-xl shadow-2xl max-h-60 overflow-y-auto overflow-x-hidden scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                  {suggestions.slice(0, 50).map((item, index) => (
                      <div
                          key={index}
                          onClick={() => handleSelect(item)}
                          className={`px-4 py-2 cursor-pointer text-sm transition-colors border-l-2 ${
                              index === selectedIndex 
                                  ? 'bg-slate-800 text-white border-blue-500' 
                                  : 'text-slate-300 hover:bg-slate-800 hover:text-white border-transparent'
                          }`}
                      >
                          {item}
                      </div>
                  ))}
                  {suggestions.length > 50 && (
                      <div className="px-4 py-2 text-xs text-slate-500 text-center border-t border-slate-800">
                          ...and {suggestions.length - 50} more
                      </div>
                  )}
              </div>
          )}
      </div>
  );
};

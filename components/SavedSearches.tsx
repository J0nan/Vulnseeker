import React, { useState, useRef } from 'react';
import { SavedSearch } from '../types';
import { Trash2, FolderOpen, Calendar, Bookmark, ChevronDown, ChevronUp, Edit2, Check, X, Download, Upload, FileJson, AlertCircle } from 'lucide-react';

interface SavedSearchesProps {
  searches: SavedSearch[];
  onLoad: (search: SavedSearch) => void;
  onDelete: (id: string) => void;
  onRename: (id: string, newLabel: string) => void;
  onImport: (searches: SavedSearch[]) => void;
  onClearAll: () => void;
}

export const SavedSearches: React.FC<SavedSearchesProps> = ({ searches, onLoad, onDelete, onRename, onImport, onClearAll }) => {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editLabel, setEditLabel] = useState('');
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const startEditing = (search: SavedSearch) => {
    setEditingId(search.id);
    setEditLabel(search.label);
  };

  const cancelEditing = () => {
    setEditingId(null);
    setEditLabel('');
  };

  const saveEditing = (id: string) => {
    if (editLabel.trim()) {
      onRename(id, editLabel.trim());
    }
    setEditingId(null);
  };

  const handleExportAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    if (searches.length === 0) return;
    const dataStr = JSON.stringify(searches, null, 2);
    downloadJson(dataStr, `vulnseeker-snapshots-all-${new Date().toISOString().split('T')[0]}.json`);
  };

  const handleExportSingle = (search: SavedSearch) => {
    const dataStr = JSON.stringify(search, null, 2);
    const sanitizedLabel = search.label.replace(/[^a-z0-9]/gi, '_').toLowerCase();
    downloadJson(dataStr, `vulnseeker-snapshot-${sanitizedLabel}.json`);
  };

  const downloadJson = (dataStr: string, fileName: string) => {
    const blob = new Blob([dataStr], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = fileName;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const handleImportClick = () => {
    fileInputRef.current?.click();
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const result = event.target?.result as string;
        const parsed = JSON.parse(result);
        
        let candidates: any[] = [];
        
        if (Array.isArray(parsed)) {
            candidates = parsed;
        } else if (typeof parsed === 'object' && parsed !== null) {
            // Handle single object import
            candidates = [parsed];
        }

        // Basic validation
        const validSearches = candidates.filter(item => 
            item.vendor && 
            item.product && 
            Array.isArray(item.cves)
        );

        if (validSearches.length > 0) {
          onImport(validSearches);
          // Auto-expand if we imported something
          setIsCollapsed(false);
        } else {
          alert("No valid snapshots found in file.");
        }
      } catch (err) {
        alert("Failed to parse JSON file.");
        console.error(err);
      }
      // Reset input to allow re-importing same file if needed
      if (fileInputRef.current) fileInputRef.current.value = '';
    };
    reader.readAsText(file);
  };

  const handleClearAllClick = (e: React.MouseEvent) => {
    e.stopPropagation();
    setShowClearConfirm(true);
  };

  const confirmClearAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    onClearAll();
    setShowClearConfirm(false);
  };

  const cancelClearAll = (e: React.MouseEvent) => {
    e.stopPropagation();
    setShowClearConfirm(false);
  };

  return (
    <div className="mb-10 animate-in fade-in slide-in-from-top-4 duration-500 border border-white/5 bg-slate-900/20 rounded-2xl overflow-hidden shadow-sm">
      <div className="flex flex-col md:flex-row md:items-center justify-between p-4 bg-slate-900/40 border-b border-white/5 gap-3">
        <button 
          type="button"
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="flex items-center gap-2 text-lg font-semibold text-slate-300 hover:text-white transition-colors focus:outline-none"
        >
          <Bookmark className="w-5 h-5 text-blue-400" /> 
          Saved Snapshots ({searches.length})
          {isCollapsed ? <ChevronDown className="w-4 h-4 opacity-50" /> : <ChevronUp className="w-4 h-4 opacity-50" />}
        </button>

        <div className="flex items-center gap-2 flex-wrap">
           <button 
             type="button"
             onClick={handleImportClick}
             className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg border border-slate-700 transition-colors"
             title="Import JSON file"
           >
             <Upload className="w-3.5 h-3.5" /> Import
           </button>
           <input 
             type="file" 
             ref={fileInputRef} 
             onChange={handleFileChange} 
             accept=".json" 
             className="hidden" 
           />

           {searches.length > 0 && (
             <>
                <button 
                    type="button"
                    onClick={handleExportAll}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-400 bg-slate-800 hover:bg-slate-700 hover:text-white rounded-lg border border-slate-700 transition-colors"
                    title="Export all to JSON"
                >
                    <Download className="w-3.5 h-3.5" /> Export All
                </button>
                <div className="w-px h-4 bg-slate-700 mx-1"></div>
                
                {showClearConfirm ? (
                   <div className="flex items-center gap-2 animate-in fade-in slide-in-from-right-4 duration-300 bg-red-950/30 px-2 py-1 rounded-lg border border-red-900/30">
                       <AlertCircle className="w-3.5 h-3.5 text-red-400" />
                       <span className="text-xs text-red-300 font-medium whitespace-nowrap">Delete All?</span>
                       <button 
                         type="button"
                         onClick={confirmClearAll} 
                         className="px-2 py-0.5 bg-red-600 hover:bg-red-500 text-white text-xs font-bold rounded shadow-sm transition-colors"
                       >
                         Yes
                       </button>
                       <button 
                         type="button"
                         onClick={cancelClearAll} 
                         className="px-2 py-0.5 bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs font-medium rounded transition-colors"
                       >
                         No
                       </button>
                   </div>
                ) : (
                    <button 
                        type="button"
                        onClick={handleClearAllClick}
                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-red-400 bg-red-950/20 hover:bg-red-900/40 border border-red-900/30 rounded-lg transition-colors"
                        title="Delete all snapshots"
                    >
                        <Trash2 className="w-3.5 h-3.5" /> Clear All
                    </button>
                )}
             </>
           )}
        </div>
      </div>

      {!isCollapsed && (
        <div className="p-4 bg-slate-900/20">
          {searches.length === 0 ? (
            <div className="text-center py-8 text-slate-500 border border-dashed border-slate-700 rounded-xl">
                <FileJson className="w-10 h-10 mx-auto mb-2 opacity-20" />
                <p>No snapshots saved yet.</p>
                <p className="text-xs mt-1 opacity-70">Save a search or import a JSON file.</p>
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {searches.map((search) => (
                <div key={search.id} className="bg-slate-800/40 border border-white/5 rounded-xl p-4 hover:border-blue-500/30 transition-all group relative overflow-hidden flex flex-col">
                    
                    {/* Header / Rename Logic */}
                    <div className="flex justify-between items-start mb-3 z-10 relative h-8">
                    {editingId === search.id ? (
                        <div className="flex items-center gap-1 w-full mr-2">
                        <input 
                            type="text" 
                            value={editLabel}
                            onChange={(e) => setEditLabel(e.target.value)}
                            className="w-full bg-slate-950 border border-blue-500/50 rounded px-2 py-1 text-sm text-white focus:outline-none"
                            autoFocus
                            onKeyDown={(e) => {
                            if (e.key === 'Enter') saveEditing(search.id);
                            if (e.key === 'Escape') cancelEditing();
                            }}
                        />
                        <button type="button" onClick={() => saveEditing(search.id)} className="p-1 text-green-400 hover:bg-green-500/10 rounded"><Check className="w-4 h-4" /></button>
                        <button type="button" onClick={cancelEditing} className="p-1 text-red-400 hover:bg-red-500/10 rounded"><X className="w-4 h-4" /></button>
                        </div>
                    ) : (
                        <div className="min-w-0 flex-1 flex items-start justify-between">
                        <div className="min-w-0 pr-2">
                            <h4 className="font-medium text-blue-400 truncate" title={search.label}>{search.label}</h4>
                            <div className="flex items-center gap-3 text-xs text-slate-500 mt-1">
                            <span className="flex items-center gap-1">
                                <Calendar className="w-3 h-3" />
                                {new Date(search.timestamp).toLocaleDateString()}
                            </span>
                            </div>
                        </div>
                        <div className="flex items-center">
                            <button 
                                type="button"
                                onClick={(e) => { e.stopPropagation(); handleExportSingle(search); }}
                                className="text-slate-500 hover:text-blue-400 p-1.5 rounded-md hover:bg-blue-500/10 transition-colors"
                                title="Export this snapshot"
                            >
                                <Download className="w-3.5 h-3.5" />
                            </button>
                            <button 
                            type="button"
                            onClick={(e) => { e.stopPropagation(); startEditing(search); }}
                            className="text-slate-500 hover:text-blue-400 p-1.5 rounded-md hover:bg-blue-500/10 transition-colors"
                            title="Rename"
                            >
                            <Edit2 className="w-3.5 h-3.5" />
                            </button>
                            <button 
                            type="button"
                            onClick={(e) => { e.stopPropagation(); onDelete(search.id); }}
                            className="text-slate-500 hover:text-red-400 p-1.5 rounded-md hover:bg-red-500/10 transition-colors"
                            title="Delete snapshot"
                            >
                            <Trash2 className="w-3.5 h-3.5" />
                            </button>
                        </div>
                        </div>
                    )}
                    </div>
                    
                    {/* Stats */}
                    <div className="flex items-center gap-2 mb-4 text-xs text-slate-300 bg-slate-900/50 p-2 rounded border border-white/5">
                    <span className="font-mono font-bold text-blue-400">{search.cves.length}</span> 
                    <span className="opacity-70">vulnerabilities recorded</span>
                    </div>

                    <div className="mt-auto pt-2 text-xs text-slate-500 mb-3 truncate">
                        Target: <span className="text-slate-400">{search.vendor} {search.product}</span>
                    </div>

                    <button
                    type="button"
                    onClick={() => onLoad(search)}
                    className="w-full py-2 bg-blue-600/10 hover:bg-blue-600/20 text-blue-400 text-sm font-medium rounded-lg border border-blue-500/20 hover:border-blue-500/40 transition-all flex items-center justify-center gap-2 group-hover:bg-blue-600 group-hover:text-white group-hover:border-transparent"
                    >
                    <FolderOpen className="w-4 h-4" /> Load & Search
                    </button>
                </div>
                ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
};
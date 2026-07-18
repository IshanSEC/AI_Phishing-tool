import React, { useState, useRef } from 'react';
import { 
  FileWarning, 
  Upload, 
  Download, 
  AlertOctagon, 
  ShieldCheck, 
  Server, 
  FileText,
  Binary,
  Archive,
  AlertTriangle,
  FolderOpen
} from 'lucide-react';
import axios from 'axios';
import GaugeMeter from '../components/GaugeMeter';
import { FileScanDetails } from '../types';

export const FileAnalyzer: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<FileScanDetails | null>(null);
  const [error, setError] = useState('');
  
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setResult(null);
      setError('');
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setResult(null);
      setError('');
    }
  };

  const handleClear = () => {
    setFile(null);
    setResult(null);
    setError('');
    if (fileInputRef.current) {
      fileInputRef.current.value = '';
    }
  };

  const handleAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setResult(null);
    
    if (!file) {
      setError('Please choose or drop a file to analyze.');
      return;
    }

    setLoading(true);
    const token = localStorage.getItem('token');
    
    try {
      const formData = new FormData();
      formData.append('file', file);
      
      const res = await axios.post('/api/analyze/file', formData, {
        headers: {
          'Content-Type': 'multipart/form-data',
          Authorization: `Bearer ${token}`
        }
      });
      setResult(res.data);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Server scanning process failed.');
    } finally {
      setLoading(false);
    }
  };

  const downloadPDFReport = async () => {
    if (!result) return;
    try {
      const token = localStorage.getItem('token');
      const scanId = (result as any).id || 'scan';
      const res = await axios.get(`/api/reports/download/${scanId}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `Threat_File_Report_${scanId.substring(0, 8)}.pdf`;
      link.click();
    } catch (err) {
      alert('Failed to download PDF report. Contact SOC.');
    }
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
            STATIC FILE MALWARE SCANNER
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Audit binary signatures, check headers magic mismatch, detect embedded VBA macros, and inspect PE structures</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Upload Pane */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6 border border-cyber-border/40">
            <h3 className="text-sm font-mono font-bold tracking-wider text-white uppercase mb-4 flex items-center gap-2">
              <Binary size={16} className="text-cyber-blue" />
              File Quarantine Uploader
            </h3>

            <form onSubmit={handleAnalyze} className="space-y-6">
              {!file ? (
                <div
                  onDragOver={(e) => e.preventDefault()}
                  onDrop={handleFileDrop}
                  onClick={() => fileInputRef.current?.click()}
                  className="p-12 border-2 border-dashed border-cyber-border hover:border-cyber-blue/60 hover:bg-cyber-blue/[0.01] rounded-lg flex flex-col items-center justify-center text-center cursor-pointer transition-all group"
                >
                  <Upload className="h-12 w-12 text-cyber-gray group-hover:text-cyber-blue group-hover:scale-105 transition-all mb-3" />
                  <span className="text-sm text-white font-medium">Select or drag & drop files here</span>
                  <span className="text-xs text-cyber-gray mt-1">Supports PDF, DOCX, ZIP, EXE, APK, and other formats (Max 16MB)</span>
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    className="hidden"
                  />
                </div>
              ) : (
                <div className="p-8 border border-cyber-blue/20 bg-cyber-blue/[0.01] rounded-lg flex flex-col items-center justify-center text-center relative overflow-hidden">
                  <div className="absolute top-2 right-2">
                    <button
                      type="button"
                      onClick={handleClear}
                      className="text-xs text-cyber-danger hover:underline font-mono"
                    >
                      CLEAR
                    </button>
                  </div>
                  <FileText className="h-12 w-12 text-cyber-blue mb-2 animate-pulse-slow" />
                  <span className="text-sm text-white font-mono font-semibold break-all px-4">{file.name}</span>
                  <span className="text-xs text-cyber-gray mt-1">{(file.size / 1024).toFixed(2)} KB // Quarantine Check Ready</span>
                </div>
              )}

              {error && (
                <div className="p-4 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 flex items-start gap-3 text-sm text-cyber-danger">
                  <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
                  <span>{error}</span>
                </div>
              )}

              <div className="flex justify-end gap-3">
                {file && (
                  <button
                    type="submit"
                    disabled={loading}
                    className="btn-cyber-primary px-8 py-2.5 text-xs flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <SendIcon className="h-3.5 w-3.5" />
                    {loading ? 'Performing Static Extraction...' : 'RUN METADATA AUDIT'}
                  </button>
                )}
              </div>
            </form>
          </div>

          {/* Detailed Structural Metadata Block */}
          {result && result.metadata && (
            <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2">
                STATIC PROPERTIES METADATA DRAW
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
                <div>
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">Magic Header Code</span>
                  <span className="font-semibold text-white font-mono">{result.metadata.detected_type}</span>
                </div>
                <div>
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">Compilation Timestamp</span>
                  <span className="font-semibold text-white font-mono">{result.metadata.compilation_time || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">System Architecture</span>
                  <span className="font-semibold text-white font-mono">{result.metadata.architecture || 'N/A'}</span>
                </div>
                <div>
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">Binary PE Sections Count</span>
                  <span className="font-semibold text-white font-mono">{result.metadata.num_sections || 'N/A'}</span>
                </div>
                <div className="md:col-span-2">
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">MD5 Signature Hash</span>
                  <span className="font-mono text-white select-all break-all">{result.metadata.md5}</span>
                </div>
                <div className="md:col-span-2">
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block">SHA-256 Signature Hash</span>
                  <span className="font-mono text-white select-all break-all">{result.metadata.sha256}</span>
                </div>
              </div>
              
              {/* Warnings callout if details found */}
              {result.metadata.extension_mismatch && (
                <div className="p-4 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 text-xs text-cyber-danger font-bold leading-normal">
                  CRITICAL: {result.metadata.mismatch_warning}
                </div>
              )}
              {result.metadata.double_ext && (
                <div className="p-4 rounded-lg bg-cyber-warning/10 border border-cyber-warning/30 text-xs text-cyber-warning font-bold leading-normal">
                  WARNING: {result.metadata.double_ext_warning}
                </div>
              )}
              
              {/* Sections list if PE File */}
              {result.metadata.sections && result.metadata.sections.length > 0 && (
                <div className="pt-2 border-t border-cyber-border/30">
                  <span className="text-[10px] text-cyber-gray font-mono uppercase block mb-2">Binary Section Headers</span>
                  <div className="flex flex-wrap gap-1.5">
                    {result.metadata.sections.map((sect, i) => (
                      <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded border border-cyber-border bg-white/[0.01] text-white">
                        {sect}
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {/* Right Output Verdict Panel */}
        <div className="space-y-6">
          {result ? (
            <>
              {/* Risk Gauge */}
              <div className="glass-panel p-6 border border-cyber-border/40 text-center flex flex-col items-center">
                <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 w-full mb-4">
                  FILE RISK INDEX SCORE
                </h3>
                <GaugeMeter score={result.risk_score} size={180} />
                
                <div className="mt-4 text-xs font-medium text-cyber-gray">
                  Static Risk Assessment: <span 
                    className="font-mono font-bold"
                    style={{ color: result.risk_score >= 75 ? '#ef4444' : result.risk_score >= 30 ? '#f59e0b' : '#10b981' }}
                  >
                    {result.prediction.toUpperCase()}
                  </span>
                </div>
                
                <button
                  onClick={downloadPDFReport}
                  className="mt-6 w-full px-4 py-2 border border-cyber-blue/40 text-cyber-blue hover:bg-cyber-blue/10 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-2"
                >
                  <Download size={14} />
                  COMPILE & DOWNLOAD PDF
                </button>
              </div>

              {/* Action recommendations based on score */}
              <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
                <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2">
                  SOC RECOMMENDED PROTOCOL
                </h3>
                <div className="text-xs text-cyber-gray space-y-3">
                  {result.risk_score >= 75 ? (
                    <>
                      <div className="flex gap-2">
                        <span className="text-cyber-danger font-bold">&bull;</span>
                        <span>Do NOT execute or deploy this file on client devices under any circumstances.</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="text-cyber-danger font-bold">&bull;</span>
                        <span>Submit binary SHA-256 hashes to firewall configurations to deny downloads network-wide.</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="text-cyber-danger font-bold">&bull;</span>
                        <span>Purge binary workspace cargo immediately.</span>
                      </div>
                    </>
                  ) : result.risk_score >= 30 ? (
                    <>
                      <div className="flex gap-2">
                        <span className="text-cyber-warning font-bold">&bull;</span>
                        <span>Inspect file relationships inside isolation sandboxes first before running.</span>
                      </div>
                      <div className="flex gap-2">
                        <span className="text-cyber-warning font-bold">&bull;</span>
                        <span>Verify integrity coordinates with sender origin targets.</span>
                      </div>
                    </>
                  ) : (
                    <>
                      <div className="flex gap-2">
                        <span className="text-cyber-success font-bold">&bull;</span>
                        <span>Standard verification scans passed. Safe to handle under typical terminal rules.</span>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </>
          ) : (
            <div className="glass-panel p-8 border border-cyber-border/40 text-center py-16 flex flex-col items-center">
              <Server className="h-10 w-10 text-cyber-border mb-3" />
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase">METRIC ENGINES OFF</h4>
              <p className="text-xs text-cyber-gray mt-2 max-w-[200px]">Upload threat payloads to quarantine zone to run static analysis audits.</p>
            </div>
          )}
        </div>
      </div>

      {/* Static Explanations Rules block */}
      {result && result.xai_indicators && (
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold tracking-widest text-white uppercase flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-cyber-blue"></span>
            Static Analysis Verdict Flags
          </h2>
          
          {result.xai_indicators.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {result.xai_indicators.map((ind, index) => {
                const isHigh = ind.severity === 'High';
                const isMed = ind.severity === 'Medium';
                
                return (
                  <div 
                    key={index} 
                    className={`glass-panel p-5 border transition-all flex flex-col justify-between
                      ${isHigh 
                        ? 'border-cyber-danger/40 hover:border-cyber-danger/60 shadow-[0_0_10px_rgba(239,68,68,0.05)]' 
                        : isMed 
                        ? 'border-cyber-warning/40 hover:border-cyber-warning/60 shadow-[0_0_10px_rgba(245,158,11,0.05)]' 
                        : 'border-cyber-success/40 hover:border-cyber-success/60 shadow-[0_0_10px_rgba(16,185,129,0.05)]'
                      }`}
                  >
                    <div>
                      <div className="flex justify-between items-start mb-3">
                        <h4 className="text-xs font-bold text-white font-mono tracking-wider">{ind.indicator || 'Verdict Flag'}</h4>
                        <span 
                          className={`font-bold font-mono text-[9px] px-1.5 py-0.5 rounded tracking-wide uppercase
                            ${isHigh ? 'bg-cyber-danger/10 text-cyber-danger' : isMed ? 'bg-cyber-warning/10 text-cyber-warning' : 'bg-cyber-success/10 text-cyber-success'}
                          `}
                        >
                          {ind.severity} Risk
                        </span>
                      </div>
                      <p className="text-xs text-cyber-gray leading-relaxed mb-4">{ind.explanation}</p>
                    </div>

                    <div className="pt-3 border-t border-cyber-border/40 text-xs">
                      <span className="text-[9px] text-cyber-gray uppercase font-mono block mb-1">Details Context</span>
                      <span className="font-semibold text-white font-mono break-all">{ind.details}</span>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="glass-panel p-6 border border-cyber-success/40 text-xs text-cyber-success flex items-center gap-3">
              <ShieldCheck className="h-5 w-5" />
              <span>Zero malicious binary structures or script triggers detected in static audit filters.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

// Simple inline arrow/send icon
const SendIcon = ({ className }: { className?: string }) => (
  <svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" strokeWidth={2} stroke="currentColor" className={className}>
    <path strokeLinecap="round" strokeLinejoin="round" d="M6 12 3.269 3.125A59.769 59.769 0 0 1 21.485 12 59.768 59.768 0 0 1 3.27 20.875L5.999 12Zm0 0h7.5" />
  </svg>
);

export default FileAnalyzer;

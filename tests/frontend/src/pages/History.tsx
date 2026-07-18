import React, { useState, useEffect } from 'react';
import { 
  Search, 
  Filter, 
  Trash2, 
  Download, 
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Mail,
  FileWarning,
  AlertTriangle,
  RefreshCw
} from 'lucide-react';
import axios from 'axios';
import { ScanRecord } from '../types';

export const History: React.FC = () => {
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  
  // Filter States
  const [search, setSearch] = useState('');
  const [typeFilter, setTypeFilter] = useState('');
  const [predictionFilter, setPredictionFilter] = useState('');
  const [riskFilter, setRiskFilter] = useState('');
  
  // Expanded row tracking
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const fetchHistory = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      const params: any = {};
      if (search) params.search = search;
      if (typeFilter) params.type = typeFilter;
      if (predictionFilter) params.prediction = predictionFilter;
      if (riskFilter) params.risk = riskFilter;

      const res = await axios.get('/api/history', {
        headers: { Authorization: `Bearer ${token}` },
        params
      });
      setScans(res.data);
    } catch (err) {
      setError('Failed to fetch history logs.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchHistory();
  }, [typeFilter, predictionFilter, riskFilter]); // Refetch when filters change

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    fetchHistory();
  };

  const handleDelete = async (e: React.MouseEvent, id: string) => {
    e.stopPropagation(); // Avoid expanding row when clicking delete
    if (!window.confirm('Are you sure you want to delete this threat scan log?')) return;
    
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/history/${id}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setScans(scans.filter(s => s.id !== id));
      if (expandedId === id) setExpandedId(null);
    } catch (err) {
      alert('Deletion failed. Verify credentials.');
    }
  };

  const handleDownload = async (e: React.MouseEvent, scan: ScanRecord) => {
    e.stopPropagation();
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get(`/api/reports/download/${scan.id}`, {
        headers: { Authorization: `Bearer ${token}` },
        responseType: 'blob'
      });
      
      const blob = new Blob([res.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `Threat_Report_${scan.id.substring(0, 8)}.pdf`;
      link.click();
    } catch (err) {
      alert('Failed compiling PDF. Verify socket connection.');
    }
  };

  const toggleRow = (id: string) => {
    setExpandedId(expandedId === id ? null : id);
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-cyber-border pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
            THREAT RADAR HISTORICAL LOGS
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Audit previous analysis payloads, filter results, and download archived PDF reports</p>
        </div>
        <button
          onClick={fetchHistory}
          className="p-2 border border-cyber-border rounded-lg text-cyber-gray hover:text-cyber-blue transition-colors"
          title="Refresh Logs"
        >
          <RefreshCw size={16} />
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="glass-panel p-4 border border-cyber-border/40">
        <form onSubmit={handleSearchSubmit} className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {/* Keyword Search */}
          <div className="relative md:col-span-2">
            <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-gray">
              <Search size={14} />
            </span>
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search filename, subject or email body..."
              className="w-full bg-white/[0.01] border border-cyber-border/80 rounded-lg pl-9 pr-4 py-2 text-xs text-white focus:outline-none focus:border-cyber-blue transition-all"
            />
          </div>

          {/* Type filter */}
          <div>
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              className="w-full bg-[#050816] border border-cyber-border/80 rounded-lg px-3 py-2 text-xs text-cyber-gray focus:outline-none focus:border-cyber-blue transition-all"
            >
              <option value="">All Formats (Email / File)</option>
              <option value="email">Email Scans</option>
              <option value="file">File Scans</option>
            </select>
          </div>

          {/* Verdict filter */}
          <div>
            <select
              value={predictionFilter}
              onChange={(e) => setPredictionFilter(e.target.value)}
              className="w-full bg-[#050816] border border-cyber-border/80 rounded-lg px-3 py-2 text-xs text-cyber-gray focus:outline-none focus:border-cyber-blue transition-all"
            >
              <option value="">All Verdicts</option>
              <option value="Safe">Safe / Legitimate</option>
              <option value="Phishing">Phishing</option>
              <option value="Suspicious">Suspicious</option>
              <option value="Malicious">Malicious</option>
            </select>
          </div>

          {/* Risk Level Filter */}
          <div>
            <select
              value={riskFilter}
              onChange={(e) => setRiskFilter(e.target.value)}
              className="w-full bg-[#050816] border border-cyber-border/80 rounded-lg px-3 py-2 text-xs text-cyber-gray focus:outline-none focus:border-cyber-blue transition-all"
            >
              <option value="">All Risk Tiers</option>
              <option value="Low">Low Risk (&lt;30%)</option>
              <option value="Medium">Medium Risk (30-75%)</option>
              <option value="High">High Risk (&gt;75%)</option>
            </select>
          </div>
        </form>
      </div>

      {/* Logs Table */}
      {loading ? (
        <div className="space-y-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-12 glass-panel skeleton-loading"></div>
          ))}
        </div>
      ) : scans.length > 0 ? (
        <div className="glass-panel border border-cyber-border/40 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border/60 text-[10px] text-cyber-gray uppercase font-mono tracking-wider bg-white/[0.01]">
                  <th className="py-3 pl-4">Target Name</th>
                  <th className="py-3">Category</th>
                  <th className="py-3">Verdict</th>
                  <th className="py-3">Threat score</th>
                  <th className="py-3">Audit Date</th>
                  <th className="py-3 text-right pr-4">Actions</th>
                </tr>
              </thead>
              <tbody className="text-xs divide-y divide-cyber-border/30">
                {scans.map((scan) => {
                  const isExpanded = expandedId === scan.id;
                  const isThreat = ['Phishing', 'Suspicious', 'Malicious'].includes(scan.prediction);
                  
                  return (
                    <React.Fragment key={scan.id}>
                      {/* Base row */}
                      <tr 
                        onClick={() => toggleRow(scan.id)}
                        className="hover:bg-white/[0.01] transition-all cursor-pointer select-none"
                      >
                        <td className="py-4 pl-4 font-medium text-white truncate max-w-[220px]">
                          <div className="flex items-center gap-3">
                            {scan.type === 'email' 
                              ? <Mail size={14} className="text-cyber-blue/80" /> 
                              : <FileWarning size={14} className="text-cyber-danger/80" />
                            }
                            <span className="truncate">{scan.name}</span>
                          </div>
                        </td>
                        <td className="py-4 font-mono text-[10px] uppercase text-cyber-gray">
                          {scan.type === 'email' ? 'Email Payload' : 'Binary File'}
                        </td>
                        <td className="py-4">
                          <span 
                            className={`font-bold px-2 py-0.5 rounded text-[10px] tracking-wider uppercase
                              ${isThreat ? 'bg-cyber-danger/10 text-cyber-danger' : 'bg-cyber-success/10 text-cyber-success'}
                            `}
                          >
                            {scan.prediction}
                          </span>
                        </td>
                        <td className="py-4 font-mono font-bold">
                          <span style={{ color: scan.risk_score >= 75 ? '#ef4444' : scan.risk_score >= 30 ? '#f59e0b' : '#10b981' }}>
                            {scan.risk_score}%
                          </span>
                        </td>
                        <td className="py-4 text-cyber-gray font-mono text-[10px]">
                          {new Date(scan.created_at).toLocaleString()}
                        </td>
                        <td className="py-4 text-right pr-4" onClick={e => e.stopPropagation()}>
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={(e) => handleDownload(e, scan)}
                              className="p-1.5 border border-cyber-border rounded hover:text-cyber-blue hover:border-cyber-blue/40 transition-colors"
                              title="Download PDF"
                            >
                              <Download size={12} />
                            </button>
                            <button
                              onClick={(e) => handleDelete(e, scan.id)}
                              className="p-1.5 border border-cyber-border rounded hover:text-cyber-danger hover:border-cyber-danger/40 transition-colors"
                              title="Delete Record"
                            >
                              <Trash2 size={12} />
                            </button>
                            <span className="text-cyber-gray pl-1">
                              {isExpanded ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
                            </span>
                          </div>
                        </td>
                      </tr>
                      
                      {/* Expanded XAI / Metadata breakdown */}
                      {isExpanded && (
                        <tr>
                          <td colSpan={6} className="bg-white/[0.005] p-5 border-t border-b border-cyber-border/40">
                            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 text-xs text-cyber-gray">
                              {/* Left parameters */}
                              <div className="space-y-3 lg:col-span-1 border-r border-cyber-border/40 pr-4">
                                <h5 className="font-mono text-[10px] font-bold text-cyber-blue uppercase tracking-widest mb-2">Technical Properties</h5>
                                <div>
                                  <span className="text-[9px] uppercase block font-mono">Scan Log ID</span>
                                  <span className="text-white font-mono">{scan.id}</span>
                                </div>
                                {scan.type === 'email' ? (
                                  <>
                                    <div>
                                      <span className="text-[9px] uppercase block font-mono">Sender coordinates</span>
                                      <span className="text-white">{(scan.details as any).sender_name} &lt;{(scan.details as any).sender_email}&gt;</span>
                                    </div>
                                    <div>
                                      <span className="text-[9px] uppercase block font-mono">Domain Spoofing Flags</span>
                                      <span className="text-white">Mismatched reply: {(scan.details as any).mismatched_reply_to ? 'True' : 'False'}</span>
                                    </div>
                                  </>
                                ) : (
                                  <>
                                    <div>
                                      <span className="text-[9px] uppercase block font-mono">Hash (SHA-256)</span>
                                      <span className="text-white font-mono break-all">{(scan.details as any).metadata?.sha256}</span>
                                    </div>
                                    <div>
                                      <span className="text-[9px] uppercase block font-mono">Magic header type</span>
                                      <span className="text-white font-mono">{(scan.details as any).metadata?.detected_type}</span>
                                    </div>
                                  </>
                                )}
                              </div>

                              {/* Right details: Matched XAI indicators list */}
                              <div className="lg:col-span-2 space-y-4">
                                <h5 className="font-mono text-[10px] font-bold text-cyber-blue uppercase tracking-widest">Explainable AI Highlights</h5>
                                
                                {scan.details.xai_indicators && scan.details.xai_indicators.length > 0 ? (
                                  <div className="space-y-3">
                                    {scan.details.xai_indicators.map((ind, i) => (
                                      <div key={i} className="p-3 border border-cyber-border/80 bg-[#050816] rounded-lg">
                                        <div className="flex justify-between items-center mb-1">
                                          <span className="font-bold text-white font-mono">
                                            {ind.category || ind.indicator || 'Flagged Element'}
                                          </span>
                                          <span className={`text-[9px] font-bold font-mono px-1 rounded uppercase
                                            ${ind.severity === 'High' ? 'bg-cyber-danger/10 text-cyber-danger' : ind.severity === 'Medium' ? 'bg-cyber-warning/10 text-cyber-warning' : 'bg-cyber-success/10 text-cyber-success'}
                                          `}>
                                            {ind.severity} Risk
                                          </span>
                                        </div>
                                        <p className="text-xs text-cyber-gray">{ind.description || ind.explanation}</p>
                                        <div className="mt-2 flex flex-wrap gap-1.5">
                                          {ind.matches && ind.matches.map((m, idx) => (
                                            <span key={idx} className="bg-white/[0.04] text-white px-1.5 py-0.2 rounded font-mono text-[9px]">
                                              {m}
                                            </span>
                                          ))}
                                        </div>
                                      </div>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-cyber-success text-xs flex items-center gap-2 italic">
                                    Zero flagged indicators. Standard verification passed.
                                  </div>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ) : (
        <div className="glass-panel p-12 border border-cyber-border/40 text-center py-20">
          <AlertTriangle className="h-10 w-10 text-cyber-warning mb-3 mx-auto" />
          <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase">NO SCAN ARCHIVES FOUND</h4>
          <p className="text-xs text-cyber-gray mt-2">Adjust search terms or query filters, or run new scans to log inputs.</p>
        </div>
      )}
    </div>
  );
};

export default History;

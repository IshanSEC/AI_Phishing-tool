import React, { useState, useRef } from 'react';
import {
  ShieldAlert,
  Send,
  Upload,
  FileText,
  AlertOctagon,
  ShieldCheck,
  HelpCircle,
  Download,
  AlertTriangle,
  MailWarning,
  Server
} from 'lucide-react';
import axios from 'axios';
import GaugeMeter from '../components/GaugeMeter';
import { EmailScanDetails } from '../types';

export const EmailAnalyzer: React.FC = () => {
  const [emailText, setEmailText] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<EmailScanDetails | null>(null);
  const [error, setError] = useState('');

  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const selectedFile = e.target.files[0];
      setFile(selectedFile);
      setEmailText(''); // Clear text when file uploaded
    }
  };

  const handleClear = () => {
    setEmailText('');
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

    if (!emailText.trim() && !file) {
      setError('Please paste email text content or upload an email file.');
      return;
    }

    setLoading(true);
    const token = localStorage.getItem('token');

    try {
      if (file) {
        // Multi-part file upload
        const formData = new FormData();
        formData.append('eml_file', file);

        const res = await axios.post('/api/analyze/email', formData, {
          headers: {
            'Content-Type': 'multipart/form-data',
            Authorization: `Bearer ${token}`
          }
        });
        setResult(res.data);
      } else {
        // Raw text POST
        const res = await axios.post('/api/analyze/email', { email_text: emailText }, {
          headers: { Authorization: `Bearer ${token}` }
        });
        setResult(res.data);
      }
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
        responseType: 'blob' // Required to download files
      });

      const blob = new Blob([res.data], { type: 'application/pdf' });
      const link = document.createElement('a');
      link.href = window.URL.createObjectURL(blob);
      link.download = `Threat_Analysis_Report_${scanId.substring(0, 8)}.pdf`;
      link.click();
    } catch (err) {
      alert('Failed to download PDF report. Contact SOC.');
    }
  };

  // Helper function to extract exact match highlights
  const renderHighlightedText = (text: string, indicators: any[]) => {
    if (!indicators || indicators.length === 0) return text;

    let highlighted = text;
    // Extract all keywords to highlight
    const keywords: string[] = [];
    indicators.forEach(ind => {
      if (Array.isArray(ind.matches)) {
        ind.matches.forEach((m: string) => {
          if (m.length > 2) keywords.push(m);
        });
      }
    });

    if (keywords.length === 0) return text;

    // Sort by length descending to avoid replacing sub-parts first
    keywords.sort((a, b) => b.length - a.length);
    const uniqueKeywords = Array.from(new Set(keywords));

    // Simple HTML parsing simulation
    let htmlText = text;
    uniqueKeywords.forEach(kw => {
      try {
        const escapedKw = kw.replace(/[-\/\\^$*+?.()|[\]{}]/g, '\\$&');
        const regex = new RegExp(`\\b(${escapedKw})\\b`, 'gi');
        htmlText = htmlText.replace(regex, `<span class="bg-cyber-danger/30 text-cyber-danger border-b border-cyber-danger/60 font-bold px-1 rounded">$1</span>`);
      } catch (e) { }
    });

    return <div dangerouslySetInnerHTML={{ __html: htmlText.replace(/\n/g, '<br />') }} />;
  };

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
            EMAIL ANALYZER CENTER
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Audit email text headers, check sender domains and analyze threats via explainable ML pipelines</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Input Pane */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6 border border-cyber-border/40">
            <h3 className="text-sm font-mono font-bold tracking-wider text-white uppercase mb-4 flex items-center gap-2">
              <MailWarning size={16} className="text-cyber-blue" />
              Payload Input Terminal
            </h3>

            <form onSubmit={handleAnalyze} className="space-y-4">
              {/* Tabs Paste Text vs File Upload */}
              {!file ? (
                <div>
                  <label className="block text-[10px] font-bold uppercase tracking-wider text-cyber-gray mb-2">
                    Paste Raw Email Message Header + Body Content
                  </label>
                  <textarea
                    value={emailText}
                    onChange={(e) => {
                      setEmailText(e.target.value);
                      setFile(null);
                    }}
                    placeholder="From: Security Team <alert@gmail-paypal-support.com>&#10;To: customer@company.com&#10;Subject: Account Suspended immediately!&#10;&#10;Dear user, we detected an unauthorized login attempt. Click http://verification-paypal.com to log in and verify password credentials."
                    rows={10}
                    className="w-full bg-white/[0.01] border border-cyber-border rounded-lg p-4 text-xs font-mono text-white focus:outline-none focus:border-cyber-blue transition-all"
                  />
                </div>
              ) : (
                <div className="p-8 border border-dashed border-cyber-border rounded-lg bg-cyber-blue/[0.01] flex flex-col items-center justify-center text-center">
                  <FileText className="h-12 w-12 text-cyber-blue mb-3 animate-pulse-slow" />
                  <span className="text-sm text-white font-medium">{file.name}</span>
                  <span className="text-xs text-cyber-gray mt-1">{(file.size / 1024).toFixed(2)} KB // EML Ready</span>
                  <button
                    type="button"
                    onClick={() => setFile(null)}
                    className="text-xs text-cyber-danger hover:underline mt-3"
                  >
                    Remove File
                  </button>
                </div>
              )}

              {/* Upload controls */}
              <div className="flex flex-wrap items-center justify-between gap-4 pt-2">
                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    ref={fileInputRef}
                    accept=".eml,.txt"
                    onChange={handleFileChange}
                    className="hidden"
                  />
                  <button
                    type="button"
                    onClick={() => fileInputRef.current?.click()}
                    className="px-4 py-2 border border-cyber-border rounded-lg text-xs font-semibold text-cyber-gray hover:text-white hover:border-cyber-blue transition-all flex items-center gap-2"
                  >
                    <Upload size={14} />
                    Upload .eml / .txt File
                  </button>
                </div>

                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={handleClear}
                    className="px-4 py-2 border border-transparent rounded-lg text-xs font-semibold text-cyber-gray hover:text-cyber-danger transition-all"
                  >
                    Purge Terminal
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="btn-cyber-primary px-6 py-2 text-xs flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Send size={14} />
                    {loading ? 'Evaluating Payload...' : 'AUDIT MESSAGE'}
                  </button>
                </div>
              </div>
            </form>
          </div>

          {/* Highlighted text preview block */}
          {result && !file && (
            <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2">
                THREAT INDICATION TEXT HIGHLIGHTS
              </h4>
              <div className="p-4 bg-cyber-bg border border-cyber-border rounded-lg text-xs font-mono leading-relaxed text-cyber-gray select-text max-h-80 overflow-y-auto">
                {renderHighlightedText(emailText, result.xai_indicators)}
              </div>
              <p className="text-[10px] text-cyber-gray font-mono italic">
                Note: Highlighted tokens represent triggers matching standard phishing patterns flagged by rules.
              </p>
            </div>
          )}

          {/* Active URL Resolution Scan */}
          {result && result.link_details && result.link_details.length > 0 && (
            <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-cyber-blue animate-pulse"></span>
                ACTIVE URL RESOLUTION SCAN
              </h4>
              <div className="space-y-3">
                {result.link_details.map((link, idx) => (
                  <div key={idx} className="p-3 bg-white/[0.01] border border-cyber-border/30 rounded-lg text-xs space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <span className="font-mono text-white font-semibold truncate max-w-[80%] break-all">
                        {link.url}
                      </span>
                      <span className={`font-mono text-[9px] px-1.5 py-0.5 rounded font-bold uppercase w-fit
                        ${link.has_dns ? 'bg-cyber-success/15 text-cyber-success' : 'bg-cyber-danger/15 text-cyber-danger'}
                      `}>
                        {link.has_dns ? 'DNS Resolving' : 'Dead / No IP'}
                      </span>
                    </div>

                    <div className="text-[10px] text-cyber-gray font-mono flex flex-wrap gap-x-4 gap-y-1">
                      <div>Target Domain: <span className="text-white">{link.domain}</span></div>
                      {link.resolved_ips && link.resolved_ips.length > 0 && (
                        <div>Resolved IP: <span className="text-white">{link.resolved_ips.join(', ')}</span></div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right Output Panel */}
        <div className="space-y-6">
          {/* Audit Result Display */}
          {result ? (
            <>
              {/* Threat Gauge */}
              <div className="glass-panel p-6 border border-cyber-border/40 text-center flex flex-col items-center">
                <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 w-full mb-4">
                  THREAT CLASSIFICATION INDEX
                </h3>
                <GaugeMeter score={result.risk_score} size={180} />

                <div className="mt-4 text-xs font-medium text-cyber-gray">
                  ML Prediction Confidence: <span className="font-mono text-white font-bold">{result.confidence}%</span>
                </div>

                <button
                  onClick={downloadPDFReport}
                  className="mt-6 w-full px-4 py-2 border border-cyber-blue/40 text-cyber-blue hover:bg-cyber-blue/10 rounded-lg text-xs font-bold transition-all flex items-center justify-center gap-2"
                >
                  <Download size={14} />
                  COMPILE & DOWNLOAD PDF
                </button>
              </div>

              {/* Sender & Spoofing Info */}
              <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
                <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2">
                  SENDER AUDIT FEED
                </h3>
                <div className="space-y-3 text-xs">
                  <div>
                    <span className="text-[10px] text-cyber-gray uppercase block font-mono">Sender Display Name</span>
                    <span className="font-semibold text-white">{result.sender_name}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-cyber-gray uppercase block font-mono">Sender Email Address</span>
                    <span className="font-semibold text-white font-mono break-all">{result.sender_email}</span>
                  </div>
                  <div>
                    <span className="text-[10px] text-cyber-gray uppercase block font-mono">Origination Domain</span>
                    <span className="font-semibold text-white font-mono">{result.sender_domain}</span>
                  </div>

                  {/* Status Indicator Badges */}
                  <div className="pt-2 space-y-2 border-t border-cyber-border/40">
                    {/* Domain Reputation */}
                    <div className="flex justify-between items-center py-1">
                      <span className="text-cyber-gray">Domain Reputation:</span>
                      <span className={`font-bold font-mono px-2 py-0.5 rounded text-[10px] uppercase
                        ${result.suspicious_domain ? 'bg-cyber-danger/10 text-cyber-danger' : 'bg-cyber-success/10 text-cyber-success'}
                      `}>
                        {result.suspicious_domain ? 'Suspicious' : 'Standard'}
                      </span>
                    </div>

                    {/* Spoofing */}
                    <div className="flex justify-between items-center py-1">
                      <span className="text-cyber-gray">MTA Email Spoofing Check:</span>
                      <span className={`font-bold font-mono px-2 py-0.5 rounded text-[10px] uppercase
                        ${result.possible_spoofing ? 'bg-cyber-danger/10 text-cyber-danger' : 'bg-cyber-success/10 text-cyber-success'}
                      `}>
                        {result.possible_spoofing ? 'Flagged / Mismatch' : 'Pass'}
                      </span>
                    </div>
                  </div>
                </div>
              </div>

              {/* Domain DNS Security Audit */}
              {result.dns_records && (
                <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
                  <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 flex items-center justify-between">
                    <span>DOMAIN DNS SECURITY AUDIT</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded uppercase font-bold
                      ${result.dns_records.has_dns ? 'bg-cyber-success/10 text-cyber-success' : 'bg-cyber-danger/10 text-cyber-danger'}
                    `}>
                      {result.dns_records.has_dns ? 'Resolving' : 'Unresolved / Dead'}
                    </span>
                  </h3>
                  <div className="space-y-3 text-xs">
                    {result.dns_records.resolved_ips && result.dns_records.resolved_ips.length > 0 && (
                      <div>
                        <span className="text-[10px] text-cyber-gray uppercase block font-mono">Resolved IP Address(es)</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {result.dns_records.resolved_ips.map((ip, i) => (
                            <span key={i} className="font-mono text-white bg-white/[0.04] border border-cyber-border/40 px-1.5 py-0.5 rounded text-[10px]">{ip}</span>
                          ))}
                        </div>
                      </div>
                    )}

                    <div className="flex justify-between items-center py-1 border-t border-cyber-border/30 pt-2">
                      <span className="text-cyber-gray">SPF Record Check:</span>
                      <span className={`font-bold font-mono px-2 py-0.5 rounded text-[10px] uppercase
                        ${result.dns_records.spf_record ? 'bg-cyber-success/10 text-cyber-success' : 'bg-cyber-warning/10 text-cyber-warning'}
                      `}>
                        {result.dns_records.spf_record ? 'Configured' : 'Missing'}
                      </span>
                    </div>
                    {result.dns_records.spf_record && (
                      <div className="p-2 bg-white/[0.01] border border-cyber-border/30 rounded text-[10px] font-mono text-cyber-gray break-all">
                        {result.dns_records.spf_record}
                      </div>
                    )}

                    <div className="flex justify-between items-center py-1 border-t border-cyber-border/30 pt-2">
                      <span className="text-cyber-gray">DMARC Record Check:</span>
                      <span className={`font-bold font-mono px-2 py-0.5 rounded text-[10px] uppercase
                        ${result.dns_records.dmarc_record ? 'bg-cyber-success/10 text-cyber-success' : 'bg-cyber-warning/10 text-cyber-warning'}
                      `}>
                        {result.dns_records.dmarc_record ? 'Configured' : 'Missing'}
                      </span>
                    </div>
                    {result.dns_records.dmarc_record && (
                      <div className="p-2 bg-white/[0.01] border border-cyber-border/30 rounded text-[10px] font-mono text-cyber-gray break-all">
                        {result.dns_records.dmarc_record}
                      </div>
                    )}
                  </div>
                </div>
              )}
            </>
          ) : (
            <div className="glass-panel p-8 border border-cyber-border/40 text-center py-16 flex flex-col items-center">
              <Server className="h-10 w-10 text-cyber-border mb-3" />
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase">REPORTS ENGINE OFF</h4>
              <p className="text-xs text-cyber-gray mt-2 max-w-[200px]">Input email contents or upload EML payloads to initialize audit reports feed.</p>
            </div>
          )}
        </div>
      </div>

      {/* Explainable AI Cards */}
      {result && result.xai_indicators && (
        <div className="space-y-4">
          <h2 className="text-sm font-mono font-bold tracking-widest text-white uppercase flex items-center gap-2">
            <span className="h-2.5 w-2.5 rounded-full bg-cyber-blue"></span>
            Explainable AI (XAI) Feature Cards
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
                        ? 'border-cyber-danger/40 shadow-[0_0_10px_rgba(239,68,68,0.05)] hover:border-cyber-danger/60'
                        : isMed
                          ? 'border-cyber-warning/40 shadow-[0_0_10px_rgba(245,158,11,0.05)] hover:border-cyber-warning/60'
                          : 'border-cyber-success/40 shadow-[0_0_10px_rgba(16,185,129,0.05)] hover:border-cyber-success/60'
                      }`}
                  >
                    <div>
                      <div className="flex justify-between items-start mb-3">
                        <h4 className="text-xs font-bold text-white font-mono tracking-wider">{ind.category || 'Threat Feature'}</h4>
                        <span
                          className={`font-bold font-mono text-[9px] px-1.5 py-0.5 rounded tracking-wide uppercase
                            ${isHigh ? 'bg-cyber-danger/10 text-cyber-danger' : isMed ? 'bg-cyber-warning/10 text-cyber-warning' : 'bg-cyber-success/10 text-cyber-success'}
                          `}
                        >
                          {ind.severity} Risk
                        </span>
                      </div>
                      <p className="text-xs text-cyber-gray mb-4 leading-relaxed">{ind.description || ind.explanation}</p>
                    </div>

                    <div className="pt-3 border-t border-cyber-border/40">
                      <span className="text-[9px] text-cyber-gray uppercase font-mono block mb-1.5">Matched Keywords</span>
                      <div className="flex flex-wrap gap-1.5">
                        {ind.matches.map((m, i) => (
                          <span key={i} className="text-[10px] bg-white/[0.04] border border-cyber-border/60 text-white px-2 py-0.5 rounded font-mono">
                            {m}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="glass-panel p-6 border border-cyber-success/40 text-xs text-cyber-success flex items-center gap-3">
              <ShieldCheck className="h-5 w-5" />
              <span>No suspicious patterns extracted by explainability engines. Risk scoring remains minimal.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default EmailAnalyzer;

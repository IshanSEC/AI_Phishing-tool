import React, { useState } from 'react';
import { 
  KeyRound, 
  AlertTriangle, 
  ShieldCheck, 
  ShieldAlert, 
  Eye, 
  EyeOff, 
  Check, 
  X,
  Info,
  Activity
} from 'lucide-react';
import axios from 'axios';
import { PasswordAuditResponse } from '../types';
import GaugeMeter from '../components/GaugeMeter';

export const CredentialAudit: React.FC = () => {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PasswordAuditResponse | null>(null);
  const [error, setError] = useState('');

  const handleAudit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!password) return;

    setLoading(true);
    setError('');
    setResult(null);

    try {
      const token = localStorage.getItem('token');
      const res = await axios.post('/api/security/password-audit', 
        { password },
        { headers: { Authorization: `Bearer ${token}` } }
      );
      setResult(res.data);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to perform credential audit.');
    } finally {
      setLoading(false);
    }
  };

  // Helper check results for UI checklists
  const checks = [
    { label: 'Minimum 12 Characters', met: password.length >= 12 },
    { label: 'Contains Lowercase Letter (a-z)', met: /[a-z]/.test(password) },
    { label: 'Contains Uppercase Letter (A-Z)', met: /[A-Z]/.test(password) },
    { label: 'Contains Numeric Digit (0-9)', met: /\d/.test(password) },
    { label: 'Contains Special Symbol (e.g., !@#$)', met: /[^a-zA-Z0-9]/.test(password) },
  ];

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-cyber-border pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
            CREDENTIAL SECURITY AUDITOR
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Compute cryptographic entropy and audit passwords against global leak databases using zero-trust k-anonymity</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Input Pane */}
        <div className="lg:col-span-2 space-y-6">
          <div className="glass-panel p-6 border border-cyber-border/40">
            <h3 className="text-sm font-mono font-bold tracking-wider text-white uppercase mb-4 flex items-center gap-2">
              <KeyRound size={16} className="text-cyber-blue" />
              Credential Under Test
            </h3>

            <form onSubmit={handleAudit} className="space-y-4">
              <div>
                <label className="block text-[10px] font-bold uppercase tracking-wider text-cyber-gray mb-2">
                  Password / Passphrase String
                </label>
                <div className="relative">
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter security key to evaluate..."
                    className="w-full bg-white/[0.01] border border-cyber-border rounded-lg pl-4 pr-12 py-3 text-sm font-mono text-white focus:outline-none focus:border-cyber-blue transition-all"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    className="absolute inset-y-0 right-0 pr-4 flex items-center text-cyber-gray hover:text-white transition-colors"
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
              </div>

              {/* Password checks overlay */}
              {password && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 bg-white/[0.01] border border-cyber-border/30 rounded-lg p-4">
                  {checks.map((c, i) => (
                    <div key={i} className="flex items-center gap-2 text-xs">
                      {c.met ? (
                        <span className="h-4 w-4 rounded-full bg-cyber-success/15 border border-cyber-success/30 flex items-center justify-center text-cyber-success">
                          <Check size={10} />
                        </span>
                      ) : (
                        <span className="h-4 w-4 rounded-full bg-cyber-danger/15 border border-cyber-danger/30 flex items-center justify-center text-cyber-danger">
                          <X size={10} />
                        </span>
                      )}
                      <span className={c.met ? 'text-white' : 'text-cyber-gray'}>{c.label}</span>
                    </div>
                  ))}
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-2">
                {password && (
                  <button
                    type="button"
                    onClick={() => {
                      setPassword('');
                      setResult(null);
                    }}
                    className="px-4 py-2 border border-transparent rounded-lg text-xs font-semibold text-cyber-gray hover:text-cyber-danger transition-all"
                  >
                    Clear Input
                  </button>
                )}
                <button
                  type="submit"
                  disabled={loading || !password}
                  className="btn-cyber-primary px-6 py-2.5 text-xs flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  <Activity size={14} />
                  {loading ? 'Performing Audit...' : 'RUN AUDIT'}
                </button>
              </div>
            </form>
          </div>

          {/* HIBP Audit Log Result */}
          {result && (
            <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 flex items-center gap-2">
                DATABASE LEAK EXAMINATION
              </h4>

              {result.is_leaked ? (
                <div className="p-5 rounded-lg bg-cyber-danger/10 border border-cyber-danger/35 flex items-start gap-4">
                  <div className="h-10 w-10 shrink-0 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 flex items-center justify-center text-cyber-danger">
                    <ShieldAlert size={20} />
                  </div>
                  <div>
                    <h5 className="text-sm font-bold text-white font-mono uppercase tracking-wider">COMPROMISED PASSWORD</h5>
                    <p className="text-xs text-cyber-gray mt-1 leading-relaxed">
                      Warning: This credential was discovered in <span className="text-cyber-danger font-bold font-mono text-sm">{result.leak_count.toLocaleString()}</span> known public database data leaks/breaches. An attacker could compromise your account in seconds using automated credential-stuffing dictionaries. 
                    </p>
                    <span className="inline-block mt-3 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyber-danger/10 border border-cyber-danger/30 text-cyber-danger font-mono">
                      IMMEDIATE ACTION REQUIRED: ROTATE PASSWORD
                    </span>
                  </div>
                </div>
              ) : (
                <div className="p-5 rounded-lg bg-cyber-success/10 border border-cyber-success/35 flex items-start gap-4">
                  <div className="h-10 w-10 shrink-0 rounded-lg bg-cyber-success/10 border border-cyber-success/30 flex items-center justify-center text-cyber-success">
                    <ShieldCheck size={20} />
                  </div>
                  <div>
                    <h5 className="text-sm font-bold text-white font-mono uppercase tracking-wider">SECURE IN BREACH INDEXES</h5>
                    <p className="text-xs text-cyber-gray mt-1 leading-relaxed">
                      Excellent. This exact password was not found in any indexed database leaks analyzed by the Have I Been Pwned repository.
                    </p>
                    <span className="inline-block mt-3 text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-cyber-success/10 border border-cyber-success/30 text-cyber-success font-mono">
                      STATUS: SAFE
                    </span>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Explanation panel of k-anonymity */}
          <div className="glass-panel p-6 border border-cyber-border/40 space-y-3">
            <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase flex items-center gap-2 text-cyber-blue">
              <Info size={14} />
              Zero-Trust Audit Mechanics (k-Anonymity)
            </h4>
            <p className="text-xs text-cyber-gray leading-relaxed">
              To verify if your password has been leaked, this tool uses a mathematical protocol called **k-Anonymity**:
            </p>
            <ol className="text-xs text-cyber-gray list-decimal pl-4 space-y-1.5 leading-relaxed">
              <li>The password is hashed locally in your browser/server using SHA-1 (e.g., yielding <code className="font-mono text-white text-[10px]">AAF4C61DDCC5E...</code>).</li>
              <li>Only the **first 5 characters** (<code className="font-mono text-cyber-blue text-[10px]">AAF4C</code>) are sent to the Have I Been Pwned server. The remaining 35 characters are kept completely private.</li>
              <li>The server returns a list of all leaked hashes matching those 5 characters.</li>
              <li>Our tool performs the matching check locally. **The server never knows, receives, or sees your password.**</li>
            </ol>
          </div>
        </div>

        {/* Right Info Panel */}
        <div className="space-y-6">
          {/* Entropy Gauge */}
          {result && (
            <div className="glass-panel p-6 border border-cyber-border/40 text-center flex flex-col items-center">
              <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 w-full mb-4">
                ENTROPY DENSITY
              </h3>
              
              {/* Normalize bits of entropy to 100 for gauge representation */}
              {/* Anything over 80-100 is excellent */}
              <GaugeMeter score={Math.min(100, Math.round(result.entropy_bits))} size={180} />
              
              <div className="mt-4 text-xs font-medium text-cyber-gray">
                Bits of Entropy: <span className="font-mono text-white font-bold">{result.entropy_bits}</span>
              </div>
              <div className="mt-2 text-xs font-semibold text-cyber-gray">
                Strength Class: <span className={`font-bold font-mono px-2 py-0.5 rounded text-[10px] uppercase
                  ${result.strength === 'Strong' ? 'bg-cyber-success/10 text-cyber-success' : 
                    result.strength === 'Medium' ? 'bg-cyber-warning/10 text-cyber-warning' : 
                    'bg-cyber-danger/10 text-cyber-danger'}
                `}>{result.strength}</span>
              </div>
            </div>
          )}

          {/* Audit recommendations */}
          {result && (
            <div className="glass-panel p-6 border border-cyber-border/40 space-y-4">
              <h3 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2">
                AUDIT RECOMMENDATIONS
              </h3>
              <ul className="space-y-2 text-xs text-cyber-gray">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex items-start gap-2.5 leading-relaxed">
                    <span className="h-1.5 w-1.5 rounded-full bg-cyber-blue shrink-0 mt-1.5"></span>
                    <span>{rec}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {!result && (
            <div className="glass-panel p-8 border border-cyber-border/40 text-center py-16 flex flex-col items-center">
              <KeyRound className="h-10 w-10 text-cyber-border mb-3" />
              <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase">AUDIT ENGINE OFF</h4>
              <p className="text-xs text-cyber-gray mt-2 max-w-[200px]">Input a credential candidate above to evaluate cryptographic complexity.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default CredentialAudit;

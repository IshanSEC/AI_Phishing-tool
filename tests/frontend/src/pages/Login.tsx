import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldAlert, KeyRound, Mail, AlertTriangle } from 'lucide-react';
import axios from 'axios';

export const Login: React.FC = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    // Redirect if already logged in
    if (localStorage.getItem('token')) {
      navigate('/');
    }
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);

    try {
      const response = await axios.post('/api/auth/login', { email, password });
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed to authenticate. Please check network.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-cyber-bg relative p-4">
      {/* Background Cyber Grid */}
      <div className="cyber-bg-container">
        <div className="cyber-grid"></div>
        <div className="cyber-glow-1"></div>
        <div className="cyber-glow-2"></div>
      </div>

      <div className="w-full max-w-md glass-panel p-8 relative z-10 border border-cyber-border/40">
        <div className="flex flex-col items-center mb-8">
          <div className="h-16 w-16 bg-cyber-blue/10 border border-cyber-blue/30 rounded-full flex items-center justify-center mb-3">
            <ShieldAlert className="h-9 w-9 text-cyber-blue" />
          </div>
          <h1 className="text-2xl font-bold tracking-widest text-white font-mono glow-text-blue">
            THREAT PORTAL LOGIN
          </h1>
          <p className="text-xs text-cyber-gray mt-1">AI-Powered Email & Malware Static Analysis</p>
        </div>

        {error && (
          <div className="mb-6 p-4 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 flex items-start gap-3 text-sm text-cyber-danger">
            <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
              Operator Email Address
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-gray">
                <Mail size={16} />
              </span>
              <input
                type="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="operator@company.sec"
                className="w-full bg-white/[0.02] border border-cyber-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyber-blue transition-all"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
              Security Crypt-Key (Password)
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-gray">
                <KeyRound size={16} />
              </span>
              <input
                type="password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full bg-white/[0.02] border border-cyber-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyber-blue transition-all"
              />
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full btn-cyber-primary py-3 text-sm flex items-center justify-center font-bold disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {loading ? 'Decrypting Security Profile...' : 'AUTHENTICATE SYSTEM'}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-cyber-border/40 text-center text-xs text-cyber-gray space-y-2">
          <div>
            Need access privileges?{' '}
            <Link to="/register" className="text-cyber-blue hover:underline">
              Request Operator Profile
            </Link>
          </div>
          <div className="text-[10px] text-cyber-blue/50 font-mono">
            Default Administrator: admin@threatshield.sec / AdminSecure1337!
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;

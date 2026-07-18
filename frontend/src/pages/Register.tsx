import React, { useState, useEffect } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { ShieldPlus, KeyRound, Mail, User, AlertTriangle } from 'lucide-react';
import axios from 'axios';

export const Register: React.FC = () => {
  const [name, setName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    if (localStorage.getItem('token')) {
      navigate('/');
    }
  }, [navigate]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    
    if (password.length < 8) {
      setError('Crypt-key must be at least 8 characters long.');
      return;
    }
    
    setLoading(true);

    try {
      const response = await axios.post('/api/auth/register', { name, email, password });
      localStorage.setItem('token', response.data.token);
      localStorage.setItem('user', JSON.stringify(response.data.user));
      navigate('/');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Profile request failed. Try again.');
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
            <ShieldPlus className="h-9 w-9 text-cyber-blue" />
          </div>
          <h1 className="text-2xl font-bold tracking-widest text-white font-mono glow-text-blue">
            PROVISION PROFILE
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Register New Threat Terminal Operator</p>
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
              Operator Full Name
            </label>
            <div className="relative">
              <span className="absolute inset-y-0 left-0 pl-3 flex items-center text-cyber-gray">
                <User size={16} />
              </span>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="Agent Jack Ryan"
                className="w-full bg-white/[0.02] border border-cyber-border rounded-lg pl-10 pr-4 py-2.5 text-sm text-white focus:outline-none focus:border-cyber-blue transition-all"
              />
            </div>
          </div>

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
              Security Crypt-Key (Min 8 chars)
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
            {loading ? 'Registering Security Profile...' : 'PROVISION ACCESS PROFILE'}
          </button>
        </form>

        <div className="mt-6 pt-6 border-t border-cyber-border/40 text-center text-xs text-cyber-gray">
          Already have access credentials?{' '}
          <Link to="/login" className="text-cyber-blue hover:underline">
            Authenticate Operator
          </Link>
        </div>
      </div>
    </div>
  );
};

export default Register;

import React, { useState, useEffect } from 'react';
import { User, KeyRound, AlertTriangle, ShieldCheck, Mail, Calendar } from 'lucide-react';
import axios from 'axios';

export const Profile: React.FC = () => {
  const [profile, setProfile] = useState<any>(null);
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  
  const [loading, setLoading] = useState(true);
  const [saveLoading, setSaveLoading] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');

  const fetchProfile = async () => {
    try {
      const token = localStorage.getItem('token');
      const res = await axios.get('/api/auth/profile', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setProfile(res.data);
      setName(res.data.name);
    } catch (err) {
      setError('Failed loading profile info.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchProfile();
  }, []);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setSuccess('');
    
    if (password && password !== confirmPassword) {
      setError('Confirmation password mismatch.');
      return;
    }

    if (password && password.length < 8) {
      setError('Password must be at least 8 characters.');
      return;
    }

    setSaveLoading(true);
    try {
      const token = localStorage.getItem('token');
      const res = await axios.put('/api/auth/profile', {
        name,
        ...(password && { password })
      }, {
        headers: { Authorization: `Bearer ${token}` }
      });
      
      setProfile(res.data);
      // Update local storage user details
      const localUser = JSON.parse(localStorage.getItem('user') || '{}');
      localUser.name = res.data.name;
      localStorage.setItem('user', JSON.stringify(localUser));
      
      setSuccess('Profile credentials modified successfully.');
      setPassword('');
      setConfirmPassword('');
    } catch (err: any) {
      setError(err.response?.data?.message || 'Failed saving credentials.');
    } finally {
      setSaveLoading(false);
    }
  };

  if (loading) {
    return <div className="glass-panel h-80 skeleton-loading"></div>;
  }

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="border-b border-cyber-border pb-4">
        <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
          OPERATOR CREDENTIALS CENTER
        </h1>
        <p className="text-xs text-cyber-gray mt-1">Configure profile details and manage active security access keys</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Info panel */}
        <div className="glass-panel p-6 border border-cyber-border/40 space-y-5">
          <div className="flex flex-col items-center border-b border-cyber-border pb-4">
            <div className="h-20 w-20 rounded-full bg-cyber-blue/10 border-2 border-cyber-blue/30 flex items-center justify-center text-cyber-blue font-bold text-3xl mb-3">
              {profile?.name ? profile.name[0].toUpperCase() : 'U'}
            </div>
            <h3 className="font-bold text-lg text-white leading-none">{profile?.name}</h3>
            <span className="text-[10px] text-cyber-blue font-mono font-bold tracking-widest mt-1.5 uppercase">
              {profile?.role} Operator
            </span>
          </div>

          <div className="space-y-4 text-xs">
            <div className="flex items-center gap-3">
              <Mail className="text-cyber-gray" size={16} />
              <div>
                <span className="text-[8px] uppercase font-mono block text-cyber-gray">Registered Email</span>
                <span className="font-mono text-white font-semibold">{profile?.email}</span>
              </div>
            </div>

            <div className="flex items-center gap-3">
              <Calendar className="text-cyber-gray" size={16} />
              <div>
                <span className="text-[8px] uppercase font-mono block text-cyber-gray">Account Provision Date</span>
                <span className="font-mono text-white font-semibold">
                  {profile?.created_at ? new Date(profile.created_at).toLocaleString() : 'N/A'}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* Edit Panel */}
        <div className="lg:col-span-2 glass-panel p-6 border border-cyber-border/40">
          <h3 className="text-sm font-mono font-bold tracking-wider text-white uppercase mb-6 flex items-center gap-2 border-b border-cyber-border pb-2">
            <User size={16} className="text-cyber-blue" />
            Edit Security Profile settings
          </h3>

          {error && (
            <div className="mb-6 p-4 rounded-lg bg-cyber-danger/10 border border-cyber-danger/30 flex items-start gap-3 text-sm text-cyber-danger">
              <AlertTriangle className="h-5 w-5 shrink-0 mt-0.5" />
              <span>{error}</span>
            </div>
          )}

          {success && (
            <div className="mb-6 p-4 rounded-lg bg-cyber-success/10 border border-cyber-success/30 flex items-start gap-3 text-sm text-cyber-success">
              <ShieldCheck className="h-5 w-5 shrink-0 mt-0.5" />
              <span>{success}</span>
            </div>
          )}

          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
                  Operator Name
                </label>
                <input
                  type="text"
                  required
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="w-full bg-white/[0.01] border border-cyber-border rounded-lg px-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyber-blue transition-all"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
                  Email Address (Unchangeable Coordinates)
                </label>
                <input
                  type="email"
                  disabled
                  value={profile?.email}
                  className="w-full bg-white/[0.04] border border-cyber-border/40 rounded-lg px-4 py-2.5 text-xs text-cyber-gray cursor-not-allowed font-mono"
                />
              </div>
            </div>

            <div className="pt-4 border-t border-cyber-border/40 space-y-4">
              <h4 className="text-xs font-mono font-bold tracking-wider text-cyber-blue uppercase flex items-center gap-2">
                <KeyRound size={14} />
                Modify Crypt-Key Password
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
                    New Crypt-Key (Leave empty to keep current)
                  </label>
                  <input
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-white/[0.01] border border-cyber-border rounded-lg px-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyber-blue transition-all"
                  />
                </div>

                <div>
                  <label className="block text-xs font-semibold uppercase tracking-wider text-cyber-gray mb-2">
                    Confirm New Crypt-Key
                  </label>
                  <input
                    type="password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    placeholder="••••••••"
                    className="w-full bg-white/[0.01] border border-cyber-border rounded-lg px-4 py-2.5 text-xs text-white focus:outline-none focus:border-cyber-blue transition-all"
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end pt-2">
              <button
                type="submit"
                disabled={saveLoading}
                className="btn-cyber-primary px-8 py-2.5 text-xs flex items-center justify-center font-bold disabled:opacity-50"
              >
                {saveLoading ? 'Saving Credentials...' : 'SAVE MODIFICATIONS'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </div>
  );
};

export default Profile;

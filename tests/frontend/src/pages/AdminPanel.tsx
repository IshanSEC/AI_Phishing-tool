import React, { useState, useEffect } from 'react';
import { 
  UserCheck, 
  Trash2, 
  Terminal, 
  Cpu, 
  Activity, 
  AlertTriangle, 
  Lock,
  RefreshCw,
  UserX
} from 'lucide-react';
import axios from 'axios';
import { SystemLog, User } from '../types';

export const AdminPanel: React.FC = () => {
  const [adminData, setAdminData] = useState<any>(null);
  const [usersList, setUsersList] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [deleteLoadingId, setDeleteLoadingId] = useState<string | null>(null);

  const fetchAdminDetails = async () => {
    setLoading(true);
    setError('');
    try {
      const token = localStorage.getItem('token');
      // Fetch admin stats + system logs
      const statsRes = await axios.get('/api/admin/stats', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setAdminData(statsRes.data);

      // Fetch user profiles list
      const usersRes = await axios.get('/api/admin/users', {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsersList(usersRes.data);
    } catch (err: any) {
      setError(err.response?.data?.message || 'Access denied or failed loading admin configurations.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAdminDetails();
  }, []);

  const handleDeleteUser = async (userId: string, email: string) => {
    if (userId === JSON.parse(localStorage.getItem('user') || '{}').id) {
      alert('Self-deletion of the active admin profile is forbidden.');
      return;
    }
    if (!window.confirm(`Are you sure you want to delete operator ${email}? This will purge all their threat logs too.`)) return;

    setDeleteLoadingId(userId);
    try {
      const token = localStorage.getItem('token');
      await axios.delete(`/api/admin/users/${userId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      setUsersList(usersList.filter(u => u.id !== userId));
      // Re-trigger stats count update
      fetchAdminDetails();
    } catch (err: any) {
      alert(err.response?.data?.message || 'Failed deleting user profile.');
    } finally {
      setDeleteLoadingId(null);
    }
  };

  if (loading && !adminData) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="h-44 glass-panel skeleton-loading"></div>
          <div className="h-44 glass-panel skeleton-loading"></div>
          <div className="h-44 glass-panel skeleton-loading"></div>
        </div>
        <div className="h-96 glass-panel skeleton-loading"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-panel p-8 border border-cyber-danger/30 text-center py-20">
        <Lock className="h-10 w-10 text-cyber-danger mb-3 mx-auto animate-bounce" />
        <h4 className="text-sm font-mono font-bold tracking-widest text-white uppercase glow-text-danger">ADMINISTRATIVE ACCESS DENIED</h4>
        <p className="text-xs text-cyber-gray mt-2 max-w-sm mx-auto">{error}</p>
      </div>
    );
  }

  const modelInfo = adminData?.model_diagnostics;
  const sysLogs: SystemLog[] = adminData?.logs || [];
  const summary = adminData?.summary;

  return (
    <div className="space-y-6">
      {/* Title */}
      <div className="flex justify-between items-center border-b border-cyber-border pb-4">
        <div>
          <h1 className="text-xl font-bold font-mono tracking-widest text-white glow-text-blue">
            ADMIN OPERATIONS PANEL
          </h1>
          <p className="text-xs text-cyber-gray mt-1">Audit security logs, check ML classifier hyperparameters, and manage operator database accounts</p>
        </div>
        <button
          onClick={fetchAdminDetails}
          className="p-2 border border-cyber-border rounded-lg text-cyber-gray hover:text-cyber-blue transition-colors"
          title="Refresh Controls"
        >
          <RefreshCw size={16} />
        </button>
      </div>

      {/* Model Diagnostics & Stats summary */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* ML diagnostics */}
        <div className="glass-panel p-5 border border-cyber-border/40 space-y-4">
          <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 flex items-center gap-2">
            <Cpu size={14} className="text-cyber-blue" />
            Classifier Diagnostics
          </h4>
          <div className="space-y-3 text-xs">
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Model Pipeline State</span>
              <span className={`font-bold font-mono ${modelInfo?.loaded ? 'text-cyber-success' : 'text-cyber-danger'}`}>
                {modelInfo?.loaded ? 'ACTIVE / CALIBRATED' : 'FALLBACK UNCALIBRATED'}
              </span>
            </div>
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Selected Algorithm</span>
              <span className="font-semibold text-white font-mono">{modelInfo?.algorithm || 'Keyword Matching Heuristics'}</span>
            </div>
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">TF-IDF Vector Dimensions</span>
              <span className="font-semibold text-white font-mono">{modelInfo?.features_count || 0} features</span>
            </div>
          </div>
        </div>

        {/* Global Statistics */}
        <div className="glass-panel p-5 border border-cyber-border/40 space-y-4 col-span-2">
          <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 flex items-center gap-2">
            <Activity size={14} className="text-cyber-blue" />
            Global Scan Totals Summary
          </h4>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 text-xs">
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Scans Tracked</span>
              <span className="text-lg font-bold text-white font-mono">{summary?.total_scans || 0}</span>
            </div>
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Phishing Alerts</span>
              <span className="text-lg font-bold text-cyber-danger font-mono glow-text-danger">{summary?.phishing_scans || 0}</span>
            </div>
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Average Risk Score</span>
              <span className="text-lg font-bold text-white font-mono">{summary?.average_risk_score || 0}%</span>
            </div>
            <div>
              <span className="text-[9px] text-cyber-gray font-mono uppercase block">Active Operators</span>
              <span className="text-lg font-bold text-cyber-blue font-mono glow-text-blue">{usersList.length}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Database Operators Grid */}
      <div className="glass-panel p-5 border border-cyber-border/40">
        <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 mb-4 flex items-center gap-2">
          <UserCheck size={14} className="text-cyber-blue" />
          Operator Profile Records
        </h4>
        
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse text-xs">
            <thead>
              <tr className="border-b border-cyber-border/40 text-[9px] text-cyber-gray uppercase font-mono tracking-wider">
                <th className="pb-2 pl-2">Operator Name</th>
                <th className="pb-2">Email Coordinate</th>
                <th className="pb-2">Access Role</th>
                <th className="pb-2">Provision Date</th>
                <th className="pb-2 text-right pr-2">Revoke Privileges</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-cyber-border/20">
              {usersList.map((user) => (
                <tr key={user.id} className="hover:bg-white/[0.005] transition-colors">
                  <td className="py-3 pl-2 font-medium text-white">{user.name}</td>
                  <td className="py-3 font-mono text-cyber-gray">{user.email}</td>
                  <td className="py-3">
                    <span 
                      className={`font-bold font-mono text-[9px] px-1.5 py-0.5 rounded tracking-wide uppercase
                        ${user.role === 'admin' ? 'bg-cyber-blue/10 text-cyber-blue' : 'bg-cyber-gray/10 text-cyber-gray'}
                      `}
                    >
                      {user.role}
                    </span>
                  </td>
                  <td className="py-3 text-cyber-gray font-mono text-[10px]">
                    {user.created_at ? new Date(user.created_at).toLocaleDateString() : 'N/A'}
                  </td>
                  <td className="py-3 text-right pr-2">
                    <button
                      onClick={() => handleDeleteUser(user.id, user.email)}
                      disabled={deleteLoadingId === user.id}
                      className="p-1.5 border border-cyber-border rounded hover:text-cyber-danger hover:border-cyber-danger/40 transition-colors disabled:opacity-50"
                      title="Delete User & Scans"
                    >
                      <UserX size={12} />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* System Console Logs Feed */}
      <div className="glass-panel p-5 border border-cyber-border/40">
        <h4 className="text-xs font-mono font-bold tracking-widest text-white uppercase border-b border-cyber-border/60 pb-2 mb-4 flex items-center gap-2">
          <Terminal size={14} className="text-cyber-blue" />
          Terminal Audit Logs Feed
        </h4>
        
        <div className="bg-[#03050d] border border-cyber-border rounded-lg p-4 font-mono text-[10px] leading-relaxed max-h-80 overflow-y-auto space-y-2 select-text">
          {sysLogs.length > 0 ? (
            sysLogs.map((log) => {
              const isError = log.level === 'ERROR';
              const isWarning = log.level === 'WARNING';
              const color = isError ? 'text-cyber-danger' : isWarning ? 'text-cyber-warning' : 'text-cyber-blue';
              
              return (
                <div key={log.id} className="flex flex-col sm:flex-row sm:items-start gap-1 sm:gap-4 border-b border-white/[0.02] pb-1.5">
                  <span className="text-cyber-gray shrink-0">{new Date(log.timestamp).toISOString()}</span>
                  <span className={`font-bold uppercase ${color} shrink-0 w-16`}>[{log.level}]</span>
                  <span className="text-white select-all">{log.message}</span>
                </div>
              );
            })
          ) : (
            <div className="text-center py-6 text-cyber-gray italic">
              No audit logs captured in Database logs table.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default AdminPanel;

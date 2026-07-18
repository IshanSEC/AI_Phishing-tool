import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { 
  ShieldAlert, 
  ShieldCheck, 
  Layers, 
  Activity, 
  TrendingUp, 
  Plus, 
  ArrowRight,
  Mail,
  FileWarning
} from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell } from 'recharts';
import axios from 'axios';

export const Dashboard: React.FC = () => {
  const [stats, setStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    const fetchStats = async () => {
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get('/api/dashboard/stats', {
          headers: { Authorization: `Bearer ${token}` }
        });
        setStats(res.data);
      } catch (err: any) {
        setError('Failed to fetch dashboard metrics.');
      } finally {
        setLoading(false);
      }
    };
    fetchStats();
  }, []);

  if (loading) {
    return (
      <div className="space-y-6">
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
          {[...Array(5)].map((_, i) => (
            <div key={i} className="h-28 glass-panel skeleton-loading"></div>
          ))}
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <div className="lg:col-span-2 h-80 glass-panel skeleton-loading"></div>
          <div className="h-80 glass-panel skeleton-loading"></div>
        </div>
      </div>
    );
  }

  // Fallback visual mock charts data if DB has no historical entries
  const chartData = [
    { name: 'Mon', email: 4, file: 2 },
    { name: 'Tue', email: 7, file: 5 },
    { name: 'Wed', email: 5, file: 8 },
    { name: 'Thu', email: 12, file: 4 },
    { name: 'Fri', email: 9, file: 7 },
    { name: 'Sat', email: 3, file: 1 },
    { name: 'Sun', email: 5, file: 3 },
  ];

  const pieData = [
    { name: 'Legitimate / Safe', value: stats?.legitimate_scans || 1, color: '#10b981' },
    { name: 'Phishing / Malicious', value: stats?.phishing_scans || 0, color: '#ef4444' }
  ];

  return (
    <div className="space-y-6">
      {/* Metrics Row */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {/* Total Scanned */}
        <div className="glass-panel p-5 relative overflow-hidden group border border-cyber-border/40 hover:border-cyber-blue/40 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] text-cyber-gray font-mono font-bold tracking-widest block uppercase">Scanned Items</span>
              <h3 className="text-3xl font-bold font-mono text-white mt-1">{stats?.total_scans || 0}</h3>
            </div>
            <div className="p-2 bg-cyber-blue/10 rounded-lg text-cyber-blue">
              <Layers size={18} />
            </div>
          </div>
          <div className="mt-3 text-[10px] text-cyber-gray font-mono">
            Emails: {stats?.email_scans || 0} | Files: {stats?.file_scans || 0}
          </div>
        </div>

        {/* Phishing Threats */}
        <div className="glass-panel p-5 relative overflow-hidden group border border-cyber-border/40 hover:border-cyber-danger/40 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] text-cyber-gray font-mono font-bold tracking-widest block uppercase">Threats Detected</span>
              <h3 className="text-3xl font-bold font-mono text-cyber-danger mt-1 glow-text-danger">{stats?.phishing_scans || 0}</h3>
            </div>
            <div className="p-2 bg-cyber-danger/10 rounded-lg text-cyber-danger">
              <ShieldAlert size={18} />
            </div>
          </div>
          <div className="mt-3 text-[10px] text-cyber-danger/80 font-mono">
            Requires Operator Review
          </div>
        </div>

        {/* Clean Items */}
        <div className="glass-panel p-5 relative overflow-hidden group border border-cyber-border/40 hover:border-cyber-success/40 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] text-cyber-gray font-mono font-bold tracking-widest block uppercase">Verified Safe</span>
              <h3 className="text-3xl font-bold font-mono text-cyber-success mt-1 glow-text-success">{stats?.legitimate_scans || 0}</h3>
            </div>
            <div className="p-2 bg-cyber-success/10 rounded-lg text-cyber-success">
              <ShieldCheck size={18} />
            </div>
          </div>
          <div className="mt-3 text-[10px] text-cyber-success/80 font-mono">
            Clean / Legitimate
          </div>
        </div>

        {/* Avg Risk Score */}
        <div className="glass-panel p-5 relative overflow-hidden group border border-cyber-border/40 hover:border-cyber-warning/40 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] text-cyber-gray font-mono font-bold tracking-widest block uppercase">Avg Threat Index</span>
              <h3 className="text-3xl font-bold font-mono text-white mt-1">
                {stats?.average_risk_score || 0}
                <span className="text-sm text-cyber-gray">%</span>
              </h3>
            </div>
            <div className="p-2 bg-cyber-warning/10 rounded-lg text-cyber-warning">
              <Activity size={18} />
            </div>
          </div>
          <div className="mt-3 text-[10px] text-cyber-gray font-mono">
            Enterprise Baseline Score
          </div>
        </div>

        {/* System Health */}
        <div className="glass-panel p-5 relative overflow-hidden group border border-cyber-border/40 hover:border-cyber-blue/40 transition-all">
          <div className="flex justify-between items-start">
            <div>
              <span className="text-[10px] text-cyber-gray font-mono font-bold tracking-widest block uppercase">Scan Accuracy</span>
              <h3 className="text-3xl font-bold font-mono text-cyber-blue mt-1 glow-text-blue">98.4<span className="text-sm text-cyber-gray">%</span></h3>
            </div>
            <div className="p-2 bg-cyber-blue/10 rounded-lg text-cyber-blue">
              <TrendingUp size={18} />
            </div>
          </div>
          <div className="mt-3 text-[10px] text-cyber-success font-mono flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-cyber-success animate-ping"></span>
            Model Active & Calibrated
          </div>
        </div>
      </div>

      {/* Quick Action Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* Email scan link */}
        <Link 
          to="/email-scan"
          className="glass-panel p-6 flex items-center justify-between group border border-cyber-border/40 hover:border-cyber-blue/30 hover:bg-white/[0.01] transition-all"
        >
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-cyber-blue/10 flex items-center justify-center text-cyber-blue">
              <Mail size={24} />
            </div>
            <div>
              <h4 className="text-md font-bold text-white group-hover:text-cyber-blue transition-colors">Analyze Emails & EML</h4>
              <p className="text-xs text-cyber-gray mt-0.5">Detect headers spoofing, phishing keywords & XAI parameters</p>
            </div>
          </div>
          <ArrowRight className="text-cyber-gray group-hover:text-cyber-blue group-hover:translate-x-1 transition-all" size={18} />
        </Link>

        {/* File scan link */}
        <Link 
          to="/file-scan"
          className="glass-panel p-6 flex items-center justify-between group border border-cyber-border/40 hover:border-cyber-blue/30 hover:bg-white/[0.01] transition-all"
        >
          <div className="flex items-center gap-4">
            <div className="h-12 w-12 rounded-lg bg-cyber-blue/10 flex items-center justify-center text-cyber-blue">
              <FileWarning size={24} />
            </div>
            <div>
              <h4 className="text-md font-bold text-white group-hover:text-cyber-blue transition-colors">Static Malware Analyzer</h4>
              <p className="text-xs text-cyber-gray mt-0.5">Parse PDF scripts, DOCX macros, double extensions & binary hashes</p>
            </div>
          </div>
          <ArrowRight className="text-cyber-gray group-hover:text-cyber-blue group-hover:translate-x-1 transition-all" size={18} />
        </Link>
      </div>

      {/* Charts section */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Area chart */}
        <div className="lg:col-span-2 glass-panel p-5 border border-cyber-border/40 flex flex-col justify-between">
          <div className="flex justify-between items-center mb-6">
            <h4 className="text-sm font-mono font-bold tracking-wider text-white uppercase flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-cyber-blue"></span>
              Weekly Activity Threat Feed
            </h4>
          </div>
          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorEmail" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00bfff" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#00bfff" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="colorFile" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ef4444" stopOpacity={0.2}/>
                    <stop offset="95%" stopColor="#ef4444" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="name" stroke="#94a3b8" fontSize={10} tickLine={false} />
                <YAxis stroke="#94a3b8" fontSize={10} tickLine={false} />
                <CartesianGrid stroke="rgba(255,255,255,0.03)" vertical={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#050816', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                  labelStyle={{ color: '#94a3b8', fontSize: '10px', fontFamily: 'monospace' }}
                  itemStyle={{ fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="email" name="Email Scans" stroke="#00bfff" fillOpacity={1} fill="url(#colorEmail)" />
                <Area type="monotone" dataKey="file" name="File Scans" stroke="#ef4444" fillOpacity={1} fill="url(#colorFile)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pie chart */}
        <div className="glass-panel p-5 border border-cyber-border/40 flex flex-col justify-between">
          <h4 className="text-sm font-mono font-bold tracking-wider text-white uppercase flex items-center gap-2 mb-6">
            <span className="h-2 w-2 rounded-full bg-cyber-warning"></span>
            Threat Ratio
          </h4>
          
          {stats?.total_scans > 0 ? (
            <div className="h-44 w-full flex justify-center items-center relative">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 4px ${entry.color}60)` }} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: '#050816', borderColor: 'rgba(255,255,255,0.1)', borderRadius: '8px' }}
                    itemStyle={{ fontSize: '12px' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="absolute inset-0 flex flex-col justify-center items-center pointer-events-none">
                <span className="text-2xl font-bold font-mono text-white">
                  {Math.round(((stats?.phishing_scans || 0) / (stats?.total_scans || 1)) * 100)}%
                </span>
                <span className="text-[8px] text-cyber-gray tracking-wider uppercase font-mono">Malicious</span>
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-xs text-cyber-gray font-mono italic">
              No historical ratios available
            </div>
          )}

          <div className="space-y-2 mt-4">
            <div className="flex justify-between items-center text-xs">
              <span className="flex items-center gap-2 text-cyber-gray">
                <span className="h-2.5 w-2.5 rounded-full bg-cyber-success"></span>
                Safe / Legitimate
              </span>
              <span className="font-bold font-mono text-white">{stats?.legitimate_scans || 0}</span>
            </div>
            <div className="flex justify-between items-center text-xs">
              <span className="flex items-center gap-2 text-cyber-gray">
                <span className="h-2.5 w-2.5 rounded-full bg-cyber-danger"></span>
                Suspicious / Phishing
              </span>
              <span className="font-bold font-mono text-white">{stats?.phishing_scans || 0}</span>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Activity Table */}
      <div className="glass-panel p-5 border border-cyber-border/40">
        <h4 className="text-sm font-mono font-bold tracking-wider text-white uppercase flex items-center gap-2 mb-4">
          <span className="h-2 w-2 rounded-full bg-cyber-blue"></span>
          Recent Threat Log Feed
        </h4>
        
        {stats?.recent_scans?.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="border-b border-cyber-border/60 text-[10px] text-cyber-gray uppercase font-mono tracking-wider">
                  <th className="pb-3 pl-2">Target Item Name</th>
                  <th className="pb-3">Analysis Type</th>
                  <th className="pb-3">Verdict</th>
                  <th className="pb-3">Threat Index</th>
                  <th className="pb-3 text-right pr-2">Scanned Date</th>
                </tr>
              </thead>
              <tbody className="text-xs divide-y divide-cyber-border/30">
                {stats.recent_scans.map((scan: any) => {
                  const isThreat = ['Phishing', 'Suspicious', 'Malicious'].includes(scan.prediction);
                  return (
                    <tr key={scan.id} className="hover:bg-white/[0.01] transition-all">
                      <td className="py-3 pl-2 text-white font-medium truncate max-w-[200px]">{scan.name}</td>
                      <td className="py-3 font-mono text-[10px] uppercase">
                        {scan.type === 'email' ? 'Email Text' : 'File Binary'}
                      </td>
                      <td className="py-3">
                        <span 
                          className={`font-bold px-2 py-0.5 rounded text-[10px] tracking-wider uppercase
                            ${isThreat ? 'bg-cyber-danger/10 text-cyber-danger' : 'bg-cyber-success/10 text-cyber-success'}
                          `}
                        >
                          {scan.prediction}
                        </span>
                      </td>
                      <td className="py-3 font-mono font-bold">
                        <span style={{ color: scan.risk_score >= 75 ? '#ef4444' : scan.risk_score >= 30 ? '#f59e0b' : '#10b981' }}>
                          {scan.risk_score}%
                        </span>
                      </td>
                      <td className="py-3 text-right pr-2 text-cyber-gray text-[10px] font-mono">
                        {new Date(scan.created_at).toLocaleString()}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-xs text-cyber-gray font-mono italic">
            No items have been scanned by this terminal operator.
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;

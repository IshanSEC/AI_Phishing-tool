import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, Link, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ShieldAlert,
  LayoutDashboard,
  Mail,
  FileWarning,
  History,
  UserCog,
  User,
  LogOut,
  Menu,
  X,
  KeyRound
} from 'lucide-react';

// Imports of pages (will be created in subsequent steps)
import Dashboard from './pages/Dashboard';
import EmailAnalyzer from './pages/EmailAnalyzer';
import FileAnalyzer from './pages/FileAnalyzer';
import HistoryPage from './pages/History';
import AdminPanel from './pages/AdminPanel';
import Profile from './pages/Profile';
import Login from './pages/Login';
import Register from './pages/Register';
import CredentialAudit from './pages/CredentialAudit';

// Protected Route Wrapper
interface ProtectedRouteProps {
  children: React.ReactNode;
  roleRequired?: 'admin' | 'user';
}

const ProtectedRoute: React.FC<ProtectedRouteProps> = ({ children, roleRequired }) => {
  const token = localStorage.getItem('token');
  const userStr = localStorage.getItem('user');

  if (!token || !userStr) {
    return <Navigate to="/login" replace />;
  }

  const user = JSON.parse(userStr);
  if (roleRequired === 'admin' && user.role !== 'admin') {
    return <Navigate to="/" replace />;
  }

  return <>{children}</>;
};

// Animated Page Transitions Layout
const PageWrapper: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <motion.div
    initial={{ opacity: 0, y: 15 }}
    animate={{ opacity: 1, y: 0 }}
    exit={{ opacity: 0, y: -15 }}
    transition={{ duration: 0.35, ease: 'easeOut' }}
    className="w-full min-h-full flex flex-col"
  >
    {children}
  </motion.div>
);

const AppLayout: React.FC = () => {
  const location = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const user = JSON.parse(localStorage.getItem('user') || '{}');

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
  };

  const navItems = [
    { name: 'Dashboard', path: '/', icon: LayoutDashboard, role: 'user' },
    { name: 'Email Analyzer', path: '/email-scan', icon: Mail, role: 'user' },
    { name: 'File Analyzer', path: '/file-scan', icon: FileWarning, role: 'user' },
    { name: 'Credential Audit', path: '/credentials', icon: KeyRound, role: 'user' },
    { name: 'Scan History', path: '/history', icon: History, role: 'user' },
    { name: 'Admin Operations', path: '/admin', icon: UserCog, role: 'admin' },
    { name: 'My Profile', path: '/profile', icon: User, role: 'user' },
  ];

  return (
    <div className="flex min-h-screen bg-cyber-bg overflow-hidden relative">
      {/* Background Cyber Grid */}
      <div className="cyber-bg-container">
        <div className="cyber-grid"></div>
        <div className="cyber-glow-1"></div>
        <div className="cyber-glow-2"></div>
      </div>

      {/* Sidebar Navigation */}
      <aside
        className={`glass-panel border-r border-cyber-border transition-all duration-300 flex flex-col z-30
          ${sidebarOpen ? 'w-64' : 'w-20'} fixed md:relative h-screen`}
      >
        {/* Brand Header */}
        <div className="p-5 border-b border-cyber-border flex items-center justify-between">
          <div className="flex items-center gap-3">
            <ShieldAlert className="h-8 w-8 text-cyber-blue animate-pulse-slow" style={{ filter: 'drop-shadow(0 0 5px #00bfff)' }} />
            {sidebarOpen && (
              <span className="font-bold tracking-widest text-white text-lg font-mono glow-text-blue">
                ThreatShield-AI
              </span>
            )}
          </div>
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="text-cyber-gray hover:text-cyber-blue p-1 rounded transition-colors"
          >
            {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>

        {/* User Block */}
        {sidebarOpen && (
          <div className="px-5 py-4 border-b border-cyber-border bg-white/[0.01] flex items-center gap-3">
            <div className="h-10 w-10 rounded-full bg-cyber-blue/10 border border-cyber-blue/30 flex items-center justify-center text-cyber-blue font-bold">
              {user.name ? user.name[0].toUpperCase() : 'U'}
            </div>
            <div className="overflow-hidden">
              <h4 className="text-sm font-semibold truncate text-white leading-none">{user.name || 'User'}</h4>
              <span className="text-[10px] text-cyber-blue font-mono font-bold tracking-wider uppercase">
                {user.role || 'Operator'}
              </span>
            </div>
          </div>
        )}

        {/* Navigation Items */}
        <nav className="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          {navItems.map((item) => {
            // Filter menu based on user roles
            if (item.role === 'admin' && user.role !== 'admin') return null;

            const isActive = location.pathname === item.path;
            const Icon = item.icon;

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`flex items-center gap-4 px-4 py-3 rounded-lg text-sm font-medium transition-all group relative
                  ${isActive
                    ? 'bg-cyber-blue/10 border-l-2 border-cyber-blue text-white shadow-[0_0_15px_rgba(0,191,255,0.05)]'
                    : 'text-cyber-gray hover:bg-white/[0.02] hover:text-white'
                  }`}
              >
                <Icon className={`h-5 w-5 transition-colors ${isActive ? 'text-cyber-blue' : 'text-cyber-gray group-hover:text-cyber-blue'}`} />
                {sidebarOpen && <span>{item.name}</span>}
                {!sidebarOpen && (
                  <div className="absolute left-16 bg-cyber-bg border border-cyber-border text-white text-xs px-2 py-1 rounded opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none whitespace-nowrap z-50">
                    {item.name}
                  </div>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Logout Footer */}
        <div className="p-3 border-t border-cyber-border">
          <button
            onClick={handleLogout}
            className="flex items-center gap-4 w-full px-4 py-3 rounded-lg text-sm font-medium text-cyber-danger hover:bg-cyber-danger/5 transition-all group"
          >
            <LogOut className="h-5 w-5 text-cyber-danger/70 group-hover:text-cyber-danger" />
            {sidebarOpen && <span>Secure Logout</span>}
          </button>
        </div>
      </aside>

      {/* Main Panel Content */}
      <main className="flex-1 flex flex-col h-screen overflow-y-auto relative pl-20 md:pl-0">
        <header className="h-16 border-b border-cyber-border glass-panel flex items-center justify-between px-6 z-20">
          <h2 className="text-lg font-semibold text-white tracking-wide flex items-center gap-2">
            <span className="h-2 w-2 rounded-full bg-cyber-success animate-ping"></span>
            SECURE ANALYTICS TERMINAL
          </h2>
          <div className="text-xs text-cyber-gray font-mono">
            OPERATIONAL ENVIRONMENT: SECURE
          </div>
        </header>

        <div className="flex-1 p-6 z-10">
          <AnimatePresence mode="wait">
            <Routes location={location} key={location.pathname}>
              <Route path="/" element={<ProtectedRoute><PageWrapper><Dashboard /></PageWrapper></ProtectedRoute>} />
              <Route path="/email-scan" element={<ProtectedRoute><PageWrapper><EmailAnalyzer /></PageWrapper></ProtectedRoute>} />
              <Route path="/file-scan" element={<ProtectedRoute><PageWrapper><FileAnalyzer /></PageWrapper></ProtectedRoute>} />
              <Route path="/credentials" element={<ProtectedRoute><PageWrapper><CredentialAudit /></PageWrapper></ProtectedRoute>} />
              <Route path="/history" element={<ProtectedRoute><PageWrapper><HistoryPage /></PageWrapper></ProtectedRoute>} />
              <Route path="/admin" element={<ProtectedRoute roleRequired="admin"><PageWrapper><AdminPanel /></PageWrapper></ProtectedRoute>} />
              <Route path="/profile" element={<ProtectedRoute><PageWrapper><Profile /></PageWrapper></ProtectedRoute>} />
              <Route path="*" element={<Navigate to="/" replace />} />
            </Routes>
          </AnimatePresence>
        </div>
      </main>
    </div>
  );
};

const App: React.FC = () => {
  return (
    <Router>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
        <Route path="/*" element={<AppLayout />} />
      </Routes>
    </Router>
  );
};

export default App;

import React, { useState, useEffect } from 'react';
import {
  Shield, PlusCircle, LayoutDashboard, ListFilter, Activity, Server,
  CheckCircle2, AlertCircle, Layers, Terminal, User, LogIn, LogOut, Key, Lock
} from 'lucide-react';
import { getHealth, login, logout, getCurrentUser } from '../api/client';

export default function Navbar({ currentView, setCurrentView }) {
  const [health, setHealth] = useState(null);
  const [showStatusModal, setShowStatusModal] = useState(false);
  const [showAuthModal, setShowAuthModal] = useState(false);
  const [currentUser, setCurrentUser] = useState(getCurrentUser());
  const [authUsername, setAuthUsername] = useState('analyst');
  const [authPassword, setAuthPassword] = useState('AnalystPassword2026!Secure');
  const [authLoading, setAuthLoading] = useState(false);
  const [authError, setAuthError] = useState(null);

  useEffect(() => {
    getHealth()
      .then(setHealth)
      .catch(() => setHealth({ status: 'offline' }));

    const handleAuthChange = () => {
      setCurrentUser(getCurrentUser());
    };

    window.addEventListener('phishscope-auth-change', handleAuthChange);
    return () => window.removeEventListener('phishscope-auth-change', handleAuthChange);
  }, []);

  const isHealthy = health?.status === 'operational';

  const handleLoginSubmit = async (e) => {
    e.preventDefault();
    try {
      setAuthLoading(true);
      setAuthError(null);
      await login(authUsername, authPassword);
      setCurrentUser(getCurrentUser());
      setShowAuthModal(false);
    } catch (err) {
      setAuthError(err.response?.data?.error || err.message || 'Authentication failed');
    } finally {
      setAuthLoading(false);
    }
  };

  const handleLogoutClick = async () => {
    await logout();
    setCurrentUser(null);
  };

  const setCredentialsPreset = (user, pass) => {
    setAuthUsername(user);
    setAuthPassword(pass);
    setAuthError(null);
  };

  return (
    <>
      <header className="sticky top-0 z-50 bg-[#171717]/95 backdrop-blur border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 sm:h-20 flex items-center justify-between">
          {/* Logo & Brand */}
          <div
            onClick={() => setCurrentView('dashboard')}
            className="flex items-center cursor-pointer group py-1 select-none"
            title="PhishScope SOC - Return to Dashboard"
          >
            <img
              src="/logo.png"
              alt="PhishScope SOC"
              className="h-12 sm:h-14 md:h-16 w-auto object-contain transition-transform duration-200 group-hover:scale-105 drop-shadow-[0_0_16px_rgba(56,189,248,0.35)]"
            />
          </div>

          {/* Navigation Links */}
          <nav className="flex items-center gap-2">
            <button
              onClick={() => setCurrentView('dashboard')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition-all ${currentView === 'dashboard'
                ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
            >
              <LayoutDashboard className="w-4 h-4" />
              <span>Dashboard</span>
            </button>

            <button
              onClick={() => setCurrentView('investigations')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition-all ${currentView === 'investigations'
                ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
            >
              <ListFilter className="w-4 h-4" />
              <span>Investigations</span>
            </button>

            <button
              onClick={() => setCurrentView('incidents')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition-all ${currentView === 'incidents'
                ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
            >
              <Layers className="w-4 h-4 text-indigo-400" />
              <span>Incidents & SIEM</span>
            </button>

            <button
              onClick={() => setCurrentView('simulations')}
              className={`flex items-center gap-2 px-3.5 py-2 rounded-lg text-sm font-semibold transition-all ${currentView === 'simulations'
                ? 'bg-sky-500/15 text-sky-400 border border-sky-500/30'
                : 'text-slate-300 hover:text-white hover:bg-slate-800/60'
                }`}
            >
              <Terminal className="w-4 h-4 text-sky-400" />
              <span>Attack Sim & Detections</span>
            </button>

            <button
              onClick={() => setCurrentView('ingest')}
              className="flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-semibold bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 text-white shadow-md shadow-sky-500/25 transition-all ml-2"
            >
              <PlusCircle className="w-4 h-4" />
              <span>New Investigation</span>
            </button>
          </nav>

          {/* User Session & System Health Indicator */}
          <div className="flex items-center gap-2.5">
            {/* Analyst Auth Status */}
            {currentUser ? (
              <div className="flex items-center gap-1.5 bg-slate-900/90 border border-slate-800 rounded-lg px-2.5 py-1 text-xs text-slate-300">
                <div className="w-2 h-2 rounded-full bg-emerald-400"></div>
                <span className="font-semibold text-white">{currentUser.username}</span>
                <span className="text-[10px] uppercase font-mono px-1 py-0.2 bg-indigo-500/20 text-indigo-300 rounded border border-indigo-500/30">
                  {currentUser.role}
                </span>
                <button
                  onClick={handleLogoutClick}
                  title="Sign out"
                  className="text-slate-400 hover:text-rose-400 transition-colors ml-1 p-0.5"
                >
                  <LogOut className="w-3.5 h-3.5" />
                </button>
              </div>
            ) : (
              <button
                onClick={() => setShowAuthModal(true)}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800/80 transition-colors text-xs text-slate-300 font-medium"
              >
                <LogIn className="w-3.5 h-3.5 text-sky-400" />
                <span>Analyst Login</span>
              </button>
            )}

            {/* System Health Status Indicator */}
            <button
              onClick={() => setShowStatusModal(true)}
              className="flex items-center gap-2 px-3 py-1.5 rounded-lg border border-slate-800 bg-slate-900/60 hover:bg-slate-800/80 transition-colors text-xs text-slate-300"
              title="Click to view external Threat Intelligence API statuses"
            >
              <span className={`w-2 h-2 rounded-full ${isHealthy ? 'bg-emerald-400 shadow-[0_0_8px_#34d399]' : 'bg-red-400'}`}></span>
              <span>API: {isHealthy ? 'Operational' : 'Offline'}</span>
            </button>
          </div>
        </div>
      </header>

      {/* Analyst Login Modal */}
      {showAuthModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-800">
              <div className="flex items-center gap-2">
                <Lock className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-bold text-white">SOC Analyst Authentication</h3>
              </div>
              <button
                onClick={() => setShowAuthModal(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            {authError && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-800 text-xs text-red-200">
                {authError}
              </div>
            )}

            <form onSubmit={handleLoginSubmit} className="space-y-3">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Username or Email</label>
                <input
                  type="text"
                  value={authUsername}
                  onChange={(e) => setAuthUsername(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">Password</label>
                <input
                  type="password"
                  value={authPassword}
                  onChange={(e) => setAuthPassword(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-950 border border-slate-800 rounded-lg text-sm text-white focus:outline-none focus:border-sky-500"
                  required
                />
              </div>

              {/* Quick Preset Buttons */}
              <div className="pt-1">
                <span className="text-[11px] text-slate-400 block mb-1.5">Quick Demo Fill:</span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => setCredentialsPreset('analyst', 'AnalystPassword2026!Secure')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700 transition-colors"
                  >
                    Analyst
                  </button>
                  <button
                    type="button"
                    onClick={() => setCredentialsPreset('admin', 'AdminPassword2026!Secure')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700 transition-colors"
                  >
                    Admin
                  </button>
                  <button
                    type="button"
                    onClick={() => setCredentialsPreset('lead', 'LeadPassword2026!Secure')}
                    className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-xs text-slate-300 border border-slate-700 transition-colors"
                  >
                    SOC Lead
                  </button>
                </div>
              </div>

              <div className="pt-3 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAuthModal(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-xs font-semibold transition-colors"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={authLoading}
                  className="px-4 py-2 bg-sky-500 hover:bg-sky-400 text-white rounded-lg text-xs font-bold transition-colors disabled:opacity-50"
                >
                  {authLoading ? 'Signing in...' : 'Sign In'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Threat Intel Modal */}
      {showStatusModal && (
        <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-md w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between pb-4 border-b border-slate-800">
              <div className="flex items-center gap-2.5">
                <Server className="w-5 h-5 text-sky-400" />
                <h3 className="text-base font-bold text-white">System & Threat Intel Integrations</h3>
              </div>
              <button
                onClick={() => setShowStatusModal(false)}
                className="text-slate-400 hover:text-white text-lg font-bold"
              >
                ✕
              </button>
            </div>

            <div className="mt-4 space-y-3 text-sm">
              <div className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-200">Backend Flask Engine</span>
                  <span className="inline-flex items-center gap-1 text-emerald-400 text-xs font-bold">
                    <CheckCircle2 className="w-4 h-4" /> Operational
                  </span>
                </div>
              </div>

              {health?.integrations && Object.entries(health.integrations).map(([key, val]) => (
                <div key={key} className="p-3 bg-slate-950/60 rounded-xl border border-slate-800/80">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold capitalize text-slate-300">{key.replace('_', ' ')}</span>
                    <span className={`text-xs font-semibold px-2 py-0.5 rounded ${val.includes('configured') && !val.includes('not_configured')
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                      : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}>
                      {val}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            <div className="mt-5 p-3 rounded-lg bg-sky-950/30 border border-sky-800/30 text-xs text-sky-300">
              <strong>Notice:</strong> When threat intelligence API keys are not provided, the platform operates in safe Degraded Mode with local DNS, RDAP, static file magic analysis, and deterministic heuristic scoring.
            </div>

            <div className="mt-5 flex justify-end">
              <button
                onClick={() => setShowStatusModal(false)}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm font-semibold transition-colors"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}


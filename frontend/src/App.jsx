import React, { useState } from 'react';
import Navbar from './components/Navbar';
import ErrorBoundary from './components/ErrorBoundary';
import Dashboard from './pages/Dashboard';
import IngestionPage from './pages/IngestionPage';
import InvestigationList from './pages/InvestigationList';
import InvestigationDetail from './pages/InvestigationDetail/Index';
import IncidentDashboard from './pages/IncidentDashboard';
import Phase5Dashboard from './pages/Phase5Dashboard';

export default function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [selectedInvestigationId, setSelectedInvestigationId] = useState(null);

  const handleSelectInvestigation = (id) => {
    setSelectedInvestigationId(id);
    setCurrentView('detail');
  };

  const handleInvestigationComplete = (id) => {
    setSelectedInvestigationId(id);
    setCurrentView('detail');
  };

  const handleBackToDashboard = () => {
    setCurrentView('dashboard');
    setSelectedInvestigationId(null);
  };

  return (
    <div className="min-h-screen bg-[#090909] text-slate-100 flex flex-col selection:bg-sky-500 selection:text-white">
      <Navbar
        currentView={currentView}
        setCurrentView={(view) => {
          setCurrentView(view);
          if (view !== 'detail') setSelectedInvestigationId(null);
        }}
      />

      <main className="flex-1 pb-16">
        <ErrorBoundary onReset={handleBackToDashboard}>
          {currentView === 'dashboard' && (
            <Dashboard
              onSelectInvestigation={handleSelectInvestigation}
              onNewInvestigation={() => setCurrentView('ingest')}
            />
          )}

          {currentView === 'ingest' && (
            <IngestionPage
              onInvestigationComplete={handleInvestigationComplete}
            />
          )}

          {currentView === 'investigations' && (
            <InvestigationList
              onSelectInvestigation={handleSelectInvestigation}
              onNewInvestigation={() => setCurrentView('ingest')}
            />
          )}

          {currentView === 'incidents' && (
            <IncidentDashboard
              onSelectInvestigation={handleSelectInvestigation}
            />
          )}

          {currentView === 'simulations' && (
            <Phase5Dashboard />
          )}

          {currentView === 'detail' && selectedInvestigationId && (
            <InvestigationDetail
              investigationId={selectedInvestigationId}
              onBack={handleBackToDashboard}
            />
          )}
        </ErrorBoundary>
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 bg-slate-950 py-6 text-center text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <img src="/logo.png" alt="PhishScope SOC" className="h-6 w-auto object-contain opacity-70 hover:opacity-100 transition-opacity" />
            <span>PhishScope SOC AI · Automated Email Digital Forensics & Phishing Detection System</span>
          </div>
          <span className="font-mono text-slate-400">Degraded Safe Mode Supported · TLP:AMBER</span>
        </div>
      </footer>
    </div>
  );
}

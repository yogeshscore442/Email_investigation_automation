import React, { useState, useEffect } from 'react';
import { 
  ArrowLeft, Shield, FileText, Globe, Link2, Paperclip, 
  Hash, Sparkles, ClipboardList, Download, Printer, RefreshCw, AlertCircle 
} from 'lucide-react';
import { getInvestigation, getReportPdfUrl, getReportHtmlUrl } from '../../api/client';
import RiskBadge from '../../components/RiskBadge';
import VerdictBadge from '../../components/VerdictBadge';

import OverviewTab from './OverviewTab';
import HeadersTab from './HeadersTab';
import SenderIntelTab from './SenderIntelTab';
import UrlAnalysisTab from './UrlAnalysisTab';
import AttachmentTab from './AttachmentTab';
import IocExplorerTab from './IocExplorerTab';
import AiInvestigationTab from './AiInvestigationTab';
import SocReportTab from './SocReportTab';

export default function InvestigationDetail({ investigationId, onBack }) {
  const [investigation, setInvestigation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState('overview');

  const fetchInvestigation = async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await getInvestigation(investigationId);
      setInvestigation(data);
    } catch (err) {
      setError('Failed to load investigation details.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchInvestigation();
  }, [investigationId]);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] gap-3">
        <RefreshCw className="w-8 h-8 text-sky-400 animate-spin" />
        <p className="text-sm text-slate-400">Loading forensic dossier #{investigationId?.slice(0, 8)}...</p>
      </div>
    );
  }

  if (error || !investigation) {
    return (
      <div className="max-w-4xl mx-auto p-6 bg-red-950/30 border border-red-800/40 rounded-2xl text-center mt-10">
        <AlertCircle className="w-10 h-10 text-red-400 mx-auto mb-3" />
        <h3 className="text-lg font-bold text-red-300">Investigation Unavailable</h3>
        <p className="text-sm text-slate-300 mt-1">{error || 'Record could not be retrieved.'}</p>
        <button
          onClick={onBack}
          className="mt-4 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-white rounded-lg text-sm font-semibold transition-colors"
        >
          Back to List
        </button>
      </div>
    );
  }

  const tabs = [
    { id: 'overview', label: '1. Overview', icon: Shield },
    { id: 'headers', label: '2. Email Headers', icon: FileText, count: investigation.headers?.length },
    { id: 'intel', label: '3. Sender Intelligence', icon: Globe },
    { id: 'urls', label: '4. URL Analysis', icon: Link2, count: investigation.urls?.length },
    { id: 'attachments', label: '5. Attachment Forensics', icon: Paperclip, count: investigation.attachments?.length },
    { id: 'iocs', label: '6. IOC Explorer', icon: Hash, count: investigation.iocs?.length },
    { id: 'ai', label: '7. AI Investigation', icon: Sparkles },
    { id: 'report', label: '8. Final SOC Report', icon: ClipboardList }
  ];

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
      {/* Top Breadcrumb & Action Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <button
          onClick={onBack}
          className="inline-flex items-center gap-2 text-xs font-semibold text-slate-400 hover:text-white transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          <span>Back to Dashboard</span>
        </button>

        <div className="flex items-center gap-2.5">
          <a
            href={getReportPdfUrl(investigation.id)}
            download
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold shadow-md transition-colors"
          >
            <Download className="w-3.5 h-3.5" />
            <span>Download PDF</span>
          </a>

          <a
            href={getReportHtmlUrl(investigation.id)}
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold border border-slate-700 transition-colors"
          >
            <Printer className="w-3.5 h-3.5" />
            <span>Print HTML</span>
          </a>
        </div>
      </div>

      {/* Hero Dossier Header */}
      <div className="bg-gradient-to-r from-slate-900 via-slate-900/90 to-slate-950 p-6 rounded-2xl border border-slate-800 shadow-xl space-y-4">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="space-y-1">
            <span className="text-xs font-mono font-semibold uppercase text-slate-400">
              Investigation #{investigation.id.slice(0, 8).toUpperCase()}
            </span>
            <h1 className="text-xl sm:text-2xl font-extrabold text-white">
              {investigation.subject || '[No Subject]'}
            </h1>
          </div>
          <div className="flex items-center gap-3 shrink-0">
            <VerdictBadge verdict={investigation.verdict} size="lg" />
            <RiskBadge score={investigation.overall_risk_score} category={investigation.risk_category} size="lg" />
          </div>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-3 border-t border-slate-800 text-xs text-slate-400">
          <div>
            <strong className="text-slate-300">From:</strong> {investigation.sender}
          </div>
          <div>
            <strong className="text-slate-300">To:</strong> {investigation.recipient || 'N/A'}
          </div>
          <div>
            <strong className="text-slate-300">Date:</strong> {investigation.email_date || (investigation.created_at ? new Date(investigation.created_at).toLocaleString() : 'N/A')}
          </div>
        </div>
      </div>

      {/* 8 Investigation Tabs Bar */}
      <div className="flex items-center gap-1 overflow-x-auto border-b border-slate-800 pb-px scrollbar-none">
        {tabs.map((tab) => {
          const Icon = tab.icon;
          const isActive = activeTab === tab.id;
          return (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 px-4 py-3 rounded-t-xl text-xs font-semibold whitespace-nowrap transition-all border-t border-x ${
                isActive
                  ? 'bg-slate-900 text-sky-400 border-slate-800 border-b-2 border-b-sky-500 font-bold shadow-md'
                  : 'bg-transparent text-slate-400 hover:text-slate-200 border-transparent hover:bg-slate-900/40'
              }`}
            >
              <Icon className="w-3.5 h-3.5" />
              <span>{tab.label}</span>
              {tab.count !== undefined && (
                <span className={`px-1.5 py-0.2 rounded-full text-[10px] ${
                  isActive ? 'bg-sky-500/20 text-sky-300' : 'bg-slate-800 text-slate-400'
                }`}>
                  {tab.count}
                </span>
              )}
            </button>
          );
        })}
      </div>

      {/* Tab Panels */}
      <div className="pt-2">
        {activeTab === 'overview' && <OverviewTab investigation={investigation} />}
        {activeTab === 'headers' && <HeadersTab investigation={investigation} />}
        {activeTab === 'intel' && <SenderIntelTab investigation={investigation} />}
        {activeTab === 'urls' && <UrlAnalysisTab investigation={investigation} />}
        {activeTab === 'attachments' && <AttachmentTab investigation={investigation} />}
        {activeTab === 'iocs' && <IocExplorerTab investigation={investigation} />}
        {activeTab === 'ai' && <AiInvestigationTab investigation={investigation} />}
        {activeTab === 'report' && <SocReportTab investigation={investigation} />}
      </div>
    </div>
  );
}


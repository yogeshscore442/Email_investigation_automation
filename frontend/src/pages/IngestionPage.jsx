import React, { useState, useRef } from 'react';
import { 
  UploadCloud, FileText, Send, Sparkles, AlertCircle, 
  CheckCircle2, RefreshCw, Shield, HelpCircle 
} from 'lucide-react';
import { uploadEmailFile, investigateHeaders } from '../api/client';

export default function IngestionPage({ onInvestigationComplete }) {
  const [activeTab, setActiveTab] = useState('upload'); // 'upload' | 'paste'
  const [file, setFile] = useState(null);
  const [rawHeaders, setRawHeaders] = useState('');
  const [rawBody, setRawBody] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const fileInputRef = useRef(null);

  const handleFileChange = (e) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0]);
      setError(null);
    }
  };

  const handleDrop = (e) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files[0]) {
      setFile(e.dataTransfer.files[0]);
      setError(null);
    }
  };

  const handleDragOver = (e) => {
    e.preventDefault();
  };

  const submitFileUpload = async () => {
    if (!file) {
      setError('Please select or drop a .eml or .msg file to investigate.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const res = await uploadEmailFile(file);
      if (res.investigation_id) {
        onInvestigationComplete(res.investigation_id);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to upload and analyze email evidence.');
    } finally {
      setLoading(false);
    }
  };

  const submitRawPaste = async () => {
    if (!rawHeaders.trim()) {
      setError('Please paste raw email headers for analysis.');
      return;
    }
    try {
      setLoading(true);
      setError(null);
      const res = await investigateHeaders(rawHeaders, rawBody);
      if (res.investigation_id) {
        onInvestigationComplete(res.investigation_id);
      }
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to analyze raw email headers.');
    } finally {
      setLoading(false);
    }
  };

  // Pre-configured attack presets for quick testing
  const loadPreset = (presetType) => {
    setActiveTab('paste');
    if (presetType === 'cred_phish') {
      setRawHeaders(`From: "Microsoft 365 Security" <admin@office365-security-alert.xyz>
To: victim.analyst@cyberdefensecorp.internal
Reply-To: support-credentials@mail-redirect.top
Subject: URGENT: Your Microsoft 365 Password Expires Within 24 Hours
Date: Thu, 05 Nov 2026 11:21:40 -0500
Message-ID: <f839210-security-alert@office365-security-alert.xyz>
X-Originating-IP: [185.220.101.5]
Authentication-Results: mx.corp.com; spf=fail; dkim=none; dmarc=fail (p=REJECT)
Received: from vps.shadow-host.top ([185.220.101.5]) by mx.corp.com with ESMTP id hop1; Thu, 05 Nov 2026 11:22:00 -0500`);
      setRawBody(`Dear Employee,

Warning: Your corporate Microsoft 365 session and password will expire within 24 hours.
Failure to authenticate immediately will result in your corporate access being locked.

Please click here to verify your account:
http://185.220.101.5/login.php?redirect=microsoft.com

Or use our secondary access portal:
http://login.microsoft.com.account-update.xyz/auth

Regards,
Microsoft IAM Security Center`);
    } else if (presetType === 'bec_wire') {
      setRawHeaders(`From: "John Doe (CEO)" <ceo.office.direct@gmail.com>
To: finance.controller@cyberdefensecorp.internal
Reply-To: executive-wire-desk@secret-offshore-desk.com
Subject: Confidential: Immediate Acquisition Payment & Wire Transfer Required
Date: Thu, 05 Nov 2026 14:01:45 -0500
Message-ID: <bec-exec-request-20261105@gmail.com>
X-Originating-IP: [194.26.29.80]
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=none
Received: from mail-relay.external-net.org ([194.26.29.80]) by mx.corp.com with ESMTP id hop1; Thu, 05 Nov 2026 14:02:00 -0500`);
      setRawBody(`Hi Sarah,

I am currently in an all-day executive board meeting regarding a highly confidential strategic vendor acquisition.
Because this deal is strictly confidential and under NDA, please do not discuss this over the phone or with the general finance department.

We need to process an initial wire transfer of $84,500 immediately within the next 2 hours to secure the contract escrow.

Please confirm that you are at your desk so I can send through the beneficiary banking coordinates and payment invoice details right away.

Treat this with extreme urgency.

Regards,
John Doe
Chief Executive Officer`);
    } else if (presetType === 'legit') {
      setRawHeaders(`From: "Tech Updates Weekly" <newsletter@techupdates.com>
To: team@cyberdefensecorp.internal
Reply-To: newsletter@techupdates.com
Subject: Tech Updates Weekly: Cloud Security Architecture
Date: Thu, 05 Nov 2026 09:14:50 -0500
Message-ID: <20261105.newsletter@techupdates.com>
Authentication-Results: mx.corp.com; spf=pass; dkim=pass; dmarc=pass (p=REJECT)
Received: from mail.techupdates.com ([198.51.100.25]) by mx.corp.com with ESMTP id hop1; Thu, 05 Nov 2026 09:15:00 -0500`);
      setRawBody(`Hello SOC team,

Welcome to this week's edition covering modern cloud architecture, container hardening, and incident response automation.

Read the complete technical writeup on our portal: https://techupdates.com/articles/cloud-security-2026

Best regards,
The Tech Updates Editorial Staff`);
    }
  };

  return (
    <div className="max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-8">
      {/* Page Title */}
      <div>
        <h1 className="text-2xl sm:text-3xl font-extrabold text-white">Ingest Email Evidence</h1>
        <p className="text-sm text-slate-400 mt-1">
          Upload forensic email artifacts (.eml, .msg) or paste raw email headers for automated investigation.
        </p>
      </div>

      {/* Preset Test Buttons */}
      <div className="bg-slate-900/60 border border-slate-800 rounded-xl p-4 backdrop-blur">
        <div className="flex items-center gap-2 mb-3">
          <Sparkles className="w-4 h-4 text-sky-400" />
          <span className="text-xs font-bold uppercase tracking-wider text-slate-300">
            Quick SOC Threat Test Presets (1-Click Analysis)
          </span>
        </div>
        <div className="flex flex-wrap gap-2.5">
          <button
            onClick={() => loadPreset('cred_phish')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-red-500/15 hover:bg-red-500/25 text-red-300 border border-red-500/30 transition-colors"
          >
            Credential Harvesting Phishing (M365 Lure)
          </button>
          <button
            onClick={() => loadPreset('bec_wire')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-amber-500/15 hover:bg-amber-500/25 text-amber-300 border border-amber-500/30 transition-colors"
          >
            Executive BEC Impersonation (Wire Transfer)
          </button>
          <button
            onClick={() => loadPreset('legit')}
            className="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-500/15 hover:bg-emerald-500/25 text-emerald-300 border border-emerald-500/30 transition-colors"
          >
            Legitimate Clean Newsletter (SPF/DKIM/DMARC Pass)
          </button>
        </div>
      </div>

      {/* Mode Tabs */}
      <div className="flex border-b border-slate-800">
        <button
          onClick={() => setActiveTab('upload')}
          className={`flex items-center gap-2 px-6 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'upload'
              ? 'border-sky-500 text-sky-400 bg-sky-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <UploadCloud className="w-4 h-4" />
          <span>Upload File (.eml / .msg)</span>
        </button>
        <button
          onClick={() => setActiveTab('paste')}
          className={`flex items-center gap-2 px-6 py-3 text-sm font-semibold border-b-2 transition-all ${
            activeTab === 'paste'
              ? 'border-sky-500 text-sky-400 bg-sky-500/10'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <FileText className="w-4 h-4" />
          <span>Paste Raw Headers & Content</span>
        </button>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="p-4 bg-red-950/40 border border-red-800/50 rounded-xl flex items-start gap-3 text-sm text-red-300">
          <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
          <div>
            <p className="font-semibold">Ingestion Error</p>
            <p className="mt-0.5 text-xs text-red-400">{error}</p>
          </div>
        </div>
      )}

      {/* Tab 1: File Upload */}
      {activeTab === 'upload' && (
        <div className="space-y-6">
          <div
            onDrop={handleDrop}
            onDragOver={handleDragOver}
            onClick={() => fileInputRef.current?.click()}
            className="border-2 border-dashed border-slate-700 hover:border-sky-500 rounded-2xl p-10 text-center cursor-pointer transition-colors bg-slate-900/40 hover:bg-slate-900/80"
          >
            <input
              type="file"
              ref={fileInputRef}
              onChange={handleFileChange}
              accept=".eml,.msg,.txt"
              className="hidden"
            />
            <div className="w-16 h-16 rounded-full bg-sky-500/10 border border-sky-500/30 flex items-center justify-center mx-auto text-sky-400">
              <UploadCloud className="w-8 h-8" />
            </div>
            <h3 className="text-base font-bold text-white mt-4">
              {file ? file.name : 'Drag & drop suspicious .eml or .msg file here'}
            </h3>
            <p className="text-xs text-slate-400 mt-1">
              Supports RFC 822 .eml files and Outlook .msg compound binary files (Max 25MB)
            </p>
            {file && (
              <div className="mt-4 inline-flex items-center gap-2 px-3 py-1 bg-sky-500/20 text-sky-300 border border-sky-500/40 rounded-full text-xs font-semibold">
                <CheckCircle2 className="w-4 h-4 text-sky-400" />
                <span>Selected: {(file.size / 1024).toFixed(1)} KB</span>
              </div>
            )}
          </div>

          <button
            onClick={submitFileUpload}
            disabled={loading || !file}
            className="w-full flex items-center justify-center gap-2 py-3.5 px-6 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:opacity-50 text-white font-bold shadow-lg shadow-sky-500/25 transition-all text-sm"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Executing Automated Forensic Pipeline...</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span>Start Security Investigation</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* Tab 2: Raw Paste */}
      {activeTab === 'paste' && (
        <div className="space-y-5">
          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
              Raw RFC 5322 Headers <span className="text-red-400">*</span>
            </label>
            <textarea
              rows={8}
              value={rawHeaders}
              onChange={(e) => setRawHeaders(e.target.value)}
              placeholder="Paste complete email headers (From:, Received:, Authentication-Results:, Message-ID:)..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
            />
          </div>

          <div>
            <label className="block text-xs font-bold uppercase tracking-wider text-slate-300 mb-2">
              Email Body Content (Plain Text or HTML)
            </label>
            <textarea
              rows={6}
              value={rawBody}
              onChange={(e) => setRawBody(e.target.value)}
              placeholder="Paste raw email body message text or HTML content..."
              className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3.5 font-mono text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-sky-500 transition-colors"
            />
          </div>

          <button
            onClick={submitRawPaste}
            disabled={loading || !rawHeaders.trim()}
            className="w-full flex items-center justify-center gap-2 py-3.5 px-6 rounded-xl bg-gradient-to-r from-sky-500 to-blue-600 hover:from-sky-400 hover:to-blue-500 disabled:opacity-50 text-white font-bold shadow-lg shadow-sky-500/25 transition-all text-sm"
          >
            {loading ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin" />
                <span>Executing Automated Forensic Pipeline...</span>
              </>
            ) : (
              <>
                <Send className="w-4 h-4" />
                <span>Analyze Raw Headers & Content</span>
              </>
            )}
          </button>
        </div>
      )}
    </div>
  );
}


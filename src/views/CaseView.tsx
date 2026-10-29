/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  CaseMetadata,
  EvidenceFile,
  LogSource,
  ParsedEvent,
} from '../types';
import {
  FolderKanban,
  Download,
  Calendar,
  User,
  Hash,
  ShieldAlert,
  Server,
  FileText,
  AlertTriangle,
  FileJson,
  CheckCircle,
  Rocket,
  ShieldCheck,
} from 'lucide-react';
import { ForensicTooltip } from '../components/ForensicTooltip';

interface CaseViewProps {
  caseData: CaseMetadata;
  onUpdateCase: (updated: Partial<CaseMetadata>) => void;
  sources: LogSource[];
  evidenceFiles: EvidenceFile[];
  events: ParsedEvent[];
  onLoadDemoScenario: () => void;
}

export const CaseView: React.FC<CaseViewProps> = ({
  caseData,
  onUpdateCase,
  sources,
  evidenceFiles,
  events,
  onLoadDemoScenario,
}) => {
  const [downloadSuccess, setDownloadSuccess] = useState<string | null>(null);

  // Computed metrics (never hardcoded)
  const uniqueHosts = Array.from(new Set(events.map((e) => e.host).filter(Boolean)));
  const uniqueUsers = Array.from(
    new Set(events.map((e) => e.user).filter((u): u is string => Boolean(u)))
  );
  const uniqueIps = Array.from(
    new Set(events.map((e) => e.src_ip).filter((ip): ip is string => Boolean(ip)))
  );
  const authFailures = events.filter((e) => e.event_type === 'auth_fail').length;
  const privEscalations = events.filter(
    (e) => e.event_type === 'privilege_escalation'
  ).length;
  const unparsedLines = events.filter((e) => e.event_type === 'unparsed').length;

  const exportAsJson = () => {
    const data = {
      case: caseData,
      sources,
      evidenceFiles: evidenceFiles.map((f) => ({
        id: f.id,
        name: f.name,
        sizeBytes: f.sizeBytes,
        sha256: f.sha256,
        uploadedAtUtc: f.uploadedAtUtc,
      })),
      timelineEvents: events,
      exportedAtUtc: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json',
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseData.caseNumber || 'case'}-forensic-timeline.json`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadSuccess('JSON exported successfully');
    setTimeout(() => setDownloadSuccess(null), 3000);
  };

  const exportAsCsv = () => {
    const headers = [
      'Normalized UTC',
      'Confidence',
      'Host',
      'Source',
      'Service',
      'Event Type',
      'User',
      'Source IP',
      'Message',
      'Original Timestamp',
      'Line Number',
      'Line SHA-256',
      'Normalization Notes',
    ];

    const rows = events.map((e) => [
      `"${e.normalized_utc}"`,
      `"${e.confidence}"`,
      `"${e.host}"`,
      `"${e.source}"`,
      `"${e.service}"`,
      `"${e.event_type}"`,
      `"${e.user || ''}"`,
      `"${e.src_ip || ''}"`,
      `"${(e.message || '').replace(/"/g, '""')}"`,
      `"${e.original_timestamp}"`,
      e.raw_ref.lineNumber,
      `"${e.raw_ref.lineHash}"`,
      `"${(e.normalization_notes || '').replace(/"/g, '""')}"`,
    ]);

    const csvContent = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${caseData.caseNumber || 'case'}-timeline.csv`;
    a.click();
    URL.revokeObjectURL(url);
    setDownloadSuccess('CSV exported successfully');
    setTimeout(() => setDownloadSuccess(null), 3000);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Title & Actions */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <FolderKanban className="w-5 h-5 text-sky-400" />
            Case Investigation Dossier
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Incident metadata, reference date for year-less syslog inference, and live calculated forensic metrics.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {events.length === 0 && (
            <button
              onClick={onLoadDemoScenario}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded text-xs font-semibold shadow-xs transition-all cursor-pointer"
            >
              <Rocket className="w-3.5 h-3.5" />
              <span>Load SSH Demo</span>
            </button>
          )}

          <button
            onClick={exportAsCsv}
            disabled={events.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
          >
            <Download className="w-3.5 h-3.5" /> Export CSV
          </button>

          <button
            onClick={exportAsJson}
            disabled={events.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 disabled:opacity-40 text-slate-200 rounded text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
          >
            <FileJson className="w-3.5 h-3.5" /> Export JSON
          </button>
        </div>
      </div>

      {downloadSuccess && (
        <div className="p-3 bg-emerald-950/60 border border-emerald-800 rounded text-emerald-300 text-xs flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {downloadSuccess}
        </div>
      )}

      {/* Computed Forensic Summary Strip (Every metric is calculated dynamically) */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Timeline Events</span>
            <ForensicTooltip
              term="Total Events"
              explanation="All individual events parsed across all uploaded files."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-100">
            {events.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">
            {sources.length} active sources
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Evidence Files</span>
            <ForensicTooltip
              term="Evidence Files"
              explanation="Raw log files stored in IndexedDB with computed SHA-256 fingerprints."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-sky-400">
            {evidenceFiles.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">SHA-256 hashed</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Distinct Hosts</span>
            <ForensicTooltip
              term="Hosts"
              explanation="Unique machine names or server labels generating log events."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-purple-400">
            {uniqueHosts.length}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5 truncate">
            {uniqueHosts.slice(0, 2).join(', ') || 'None'}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Auth Failures</span>
            <ForensicTooltip
              term="Failed Logins"
              explanation="Failed passwords or invalid user attempts — a prime indicator of brute force."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-amber-400">
            {authFailures}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Brute-force indicator</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Privilege Esc</span>
            <ForensicTooltip
              term="Privilege Escalation"
              explanation="Sudo or su commands transitioning standard users to root permissions."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-rose-400">
            {privEscalations}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Sudo/root transitions</div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
          <div className="text-slate-400 text-[11px] mb-1 flex items-center gap-1">
            <span>Unparsed Lines</span>
            <ForensicTooltip
              term="Unparsed"
              explanation="Lines that failed syntax rules, preserved read-only to avoid dropping evidence."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-400">
            {unparsedLines}
          </div>
          <div className="text-[10px] text-slate-500 mt-0.5">Preserved untouched</div>
        </div>
      </div>

      {/* Case Details Form */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 pb-2 border-b border-slate-800 flex items-center justify-between">
          <span>Case Parameters & Year Reference</span>
          <span className="text-xs text-slate-400">
            Non-technical settings configure the forensic engine
          </span>
        </h3>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1 flex items-center gap-1">
              <span>Case Tracking Number</span>
              <ForensicTooltip
                term="Tracking Number"
                explanation="Internal identifier for this incident dossier (e.g. INC-2026-089)."
              />
            </label>
            <div className="relative">
              <Hash className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={caseData.caseNumber}
                onChange={(e) => onUpdateCase({ caseNumber: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1 flex items-center gap-1">
              <span>Lead Investigator</span>
              <ForensicTooltip
                term="Examiner Name"
                explanation="Recorded into each block of the chain-of-custody ledger for accountability."
              />
            </label>
            <div className="relative">
              <User className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={caseData.investigator}
                onChange={(e) => onUpdateCase({ investigator: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-400 mb-1 flex items-center justify-between">
              <span className="flex items-center gap-1">
                <span>Incident Reference Date</span>
                <ForensicTooltip
                  term="Syslog Year Source"
                  explanation="RFC 3164 syslogs lack a year (e.g., 'Oct 9 08:44:12'). We infer the year from this date."
                />
              </span>
              <span className="text-[10px] text-sky-400">Syslog Year Source</span>
            </label>
            <div className="relative">
              <Calendar className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
              <input
                type="date"
                value={caseData.referenceDate}
                onChange={(e) => onUpdateCase({ referenceDate: e.target.value })}
                className="w-full bg-slate-950 border border-slate-800 rounded pl-8 pr-3 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
              />
            </div>
            <p className="text-[10px] text-slate-500 mt-1">
              Infers year and computes Dec-Jan year rollovers automatically.
            </p>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-400 mb-1">
            Case Title & Operation Name
          </label>
          <input
            type="text"
            value={caseData.title}
            onChange={(e) => onUpdateCase({ title: e.target.value })}
            className="w-full bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500 font-medium"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-slate-400 mb-1">
            Incident Description & Triage Hypothesis
          </label>
          <textarea
            rows={3}
            value={caseData.description}
            onChange={(e) => onUpdateCase({ description: e.target.value })}
            className="w-full bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-200 focus:outline-none focus:border-sky-500 leading-relaxed font-mono"
          />
        </div>
      </div>

      {/* Extracted Entities Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
            <Server className="w-3.5 h-3.5 text-purple-400" />
            Detected Source IPs ({uniqueIps.length})
            <ForensicTooltip
              term="Source IPs"
              explanation="Remote client network addresses discovered in login attempts and web requests."
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {uniqueIps.length === 0 ? (
              <span className="text-xs text-slate-500">No IPs parsed yet</span>
            ) : (
              uniqueIps.map((ip) => (
                <span
                  key={ip}
                  className="px-2 py-0.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-purple-300 font-semibold"
                >
                  {ip}
                </span>
              ))
            )}
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-lg p-4">
          <div className="text-xs font-semibold text-slate-300 mb-2 flex items-center gap-1.5">
            <User className="w-3.5 h-3.5 text-amber-400" />
            Targeted / Logged User Accounts ({uniqueUsers.length})
            <ForensicTooltip
              term="User Accounts"
              explanation="Usernames specified in password attempts or sudo execution logs."
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {uniqueUsers.length === 0 ? (
              <span className="text-xs text-slate-500">No users parsed yet</span>
            ) : (
              uniqueUsers.map((user) => (
                <span
                  key={user}
                  className="px-2 py-0.5 bg-slate-950 border border-slate-800 rounded text-xs font-mono text-amber-300 font-semibold"
                >
                  {user}
                </span>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

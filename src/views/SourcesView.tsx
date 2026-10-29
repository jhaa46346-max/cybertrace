/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import { LogSource, EvidenceFile, LogFormat } from '../types';
import { autoDetectFormat } from '../parsers';
import {
  UploadCloud,
  FileText,
  Clock,
  HardDrive,
  Settings,
  RefreshCw,
  Trash2,
  CheckCircle,
  HelpCircle,
  Layers,
  Rocket,
  Globe,
} from 'lucide-react';
import { ForensicTooltip } from '../components/ForensicTooltip';

interface SourcesViewProps {
  sources: LogSource[];
  evidenceFiles: EvidenceFile[];
  onAddFiles: (files: File[]) => Promise<void>;
  onUpdateSource: (sourceId: string, updates: Partial<LogSource>) => void;
  onDeleteSource: (sourceId: string) => void;
  onReparseAll: () => void;
  onLoadDemoScenario: () => void;
}

const COMMON_TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'Europe/London',
  'Europe/Paris',
  'Europe/Berlin',
  'Asia/Kolkata',
  'Asia/Singapore',
  'Asia/Tokyo',
  'Australia/Sydney',
];

export const SourcesView: React.FC<SourcesViewProps> = ({
  sources,
  evidenceFiles,
  onAddFiles,
  onUpdateSource,
  onDeleteSource,
  onReparseAll,
  onLoadDemoScenario,
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [isUploading, setIsUploading] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      setIsUploading(true);
      await onAddFiles(Array.from(e.dataTransfer.files));
      setIsUploading(false);
    }
  };

  const handleFileInputChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setIsUploading(true);
      await onAddFiles(Array.from(e.target.files));
      setIsUploading(false);
      e.target.value = '';
    }
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Layers className="w-5 h-5 text-sky-400" />
            Log Ingestion & Timezone Setup
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Assign log files to host identities, select format parsers, configure IANA timezones, and calibrate clock skew offsets.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {sources.length === 0 && (
            <button
              onClick={onLoadDemoScenario}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded text-xs font-semibold shadow-xs transition-all"
            >
              <Rocket className="w-3.5 h-3.5" />
              <span>Load SSH Demo</span>
            </button>
          )}

          <button
            onClick={onReparseAll}
            disabled={sources.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-sky-600 hover:bg-sky-500 disabled:opacity-40 text-white rounded text-xs font-semibold shadow-xs transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" /> Re-parse All Sources
          </button>
        </div>
      </div>

      {/* Drag and Drop Zone */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`border-2 border-dashed rounded-lg p-8 text-center cursor-pointer transition-colors ${
          isDragging
            ? 'border-sky-500 bg-sky-950/30'
            : 'border-slate-800 hover:border-slate-700 bg-slate-900/50'
        }`}
      >
        <input
          ref={fileInputRef}
          type="file"
          multiple
          onChange={handleFileInputChange}
          className="hidden"
          accept=".log,.txt,.csv,text/*"
        />
        <div className="flex flex-col items-center justify-center space-y-2">
          <UploadCloud
            className={`w-10 h-10 ${
              isDragging ? 'text-sky-400' : 'text-slate-500'
            }`}
          />
          <div className="text-sm font-semibold text-slate-200">
            {isUploading
              ? 'Hashing & Ingesting Evidence...'
              : 'Drop log files here or click to browse'}
          </div>
          <p className="text-xs text-slate-400 max-w-md leading-relaxed">
            Upload multiple UNIX syslog (auth.log, syslog) or Apache/Nginx web access logs.
            Original bytes are kept read-only and preserved untouched with automatic SHA-256 calculation.
          </p>
        </div>
      </div>

      {/* Configured Sources List */}
      <div className="space-y-4">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center justify-between">
          <span>Configured Sources ({sources.length})</span>
          <span className="text-xs text-slate-400">
            Changes to timezone or skew offset update timeline events instantly
          </span>
        </h3>

        {sources.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/40 rounded-lg border border-slate-800 text-slate-400 text-xs space-y-3">
            <p>No log sources configured yet. Upload a log file above or load the demo scenario.</p>
            <button
              onClick={onLoadDemoScenario}
              className="inline-flex items-center gap-1.5 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-sky-400 rounded text-xs font-medium border border-slate-700 transition-colors"
            >
              <Rocket className="w-3.5 h-3.5" />
              <span>Load SSH Brute-Force Demo</span>
            </button>
          </div>
        ) : (
          <div className="space-y-4">
            {sources.map((src) => {
              const matchedEvidence = evidenceFiles.find(
                (f) => f.id === src.fileId
              );

              return (
                <div
                  key={src.id}
                  className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4"
                >
                  {/* Top row: Name & Host */}
                  <div className="flex flex-wrap items-center justify-between gap-3 pb-3 border-b border-slate-800">
                    <div className="flex items-center gap-3">
                      <FileText className="w-4 h-4 text-sky-400" />
                      <div>
                        <div className="font-semibold text-slate-200 text-sm">
                          {src.name}
                        </div>
                        <div className="text-[11px] font-mono text-slate-400">
                          {matchedEvidence ? (
                            <>
                              File: {matchedEvidence.name} (
                              {(matchedEvidence.sizeBytes / 1024).toFixed(1)} KB) · SHA-256:{' '}
                              {matchedEvidence.sha256.slice(0, 16)}...
                            </>
                          ) : (
                            'Custom log stream'
                          )}
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono px-2 py-0.5 rounded bg-slate-950 border border-slate-800 text-slate-300">
                        {src.eventCount ?? 0} events (
                        {src.unparsedCount ?? 0} unparsed)
                      </span>
                      <button
                        onClick={() => onDeleteSource(src.id)}
                        className="p-1.5 rounded text-slate-400 hover:text-rose-400 hover:bg-slate-800 transition-colors"
                        title="Delete source"
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>

                  {/* Settings Grid: Host, Format, TZ, Clock Offset */}
                  <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-xs">
                    {/* Host Label */}
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1 flex items-center gap-1">
                        <span>Host Label</span>
                        <ForensicTooltip
                          term="Host Label"
                          explanation="Identifier of the server that created this log file (e.g. srv-prod-auth, srv-web-01)."
                        />
                      </label>
                      <input
                        type="text"
                        value={src.hostLabel}
                        onChange={(e) =>
                          onUpdateSource(src.id, { hostLabel: e.target.value })
                        }
                        placeholder="e.g. srv-prod-auth"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                      />
                    </div>

                    {/* Parser Format */}
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1 flex items-center gap-1">
                        <span>Parser Protocol</span>
                        <ForensicTooltip
                          term="Log Format"
                          explanation="RFC 3164 is traditional Linux syslog without year; Combined Log is standard Apache/Nginx access log."
                        />
                      </label>
                      <select
                        value={src.format}
                        onChange={(e) =>
                          onUpdateSource(src.id, {
                            format: e.target.value as LogFormat,
                          })
                        }
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-sky-500"
                      >
                        <option value="rfc3164_syslog">
                          Linux Syslog / auth.log (RFC 3164)
                        </option>
                        <option value="combined_log">
                          Apache / Nginx Combined Log
                        </option>
                        <option value="generic">Generic Syslog</option>
                      </select>
                    </div>

                    {/* IANA Timezone */}
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1 flex items-center gap-1">
                        <span>Source Timezone</span>
                        <ForensicTooltip
                          term="Timezone"
                          explanation="The geographical timezone configured on the server when the log was written."
                        />
                      </label>
                      <select
                        value={src.timezone}
                        onChange={(e) =>
                          onUpdateSource(src.id, { timezone: e.target.value })
                        }
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                      >
                        {COMMON_TIMEZONES.map((tz) => (
                          <option key={tz} value={tz}>
                            {tz}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Clock Skew Offset */}
                    <div>
                      <label className="block text-[11px] font-medium text-slate-400 mb-1 flex items-center justify-between">
                        <span className="flex items-center gap-1">
                          <span>Clock Skew Offset (sec)</span>
                          <ForensicTooltip
                            term="Clock Skew"
                            explanation="If server was 3 minutes fast, enter 180s. TimelineForge subtracts 180s to find true UTC."
                          />
                        </span>
                        <span className="text-[10px] text-amber-400 font-mono">
                          {src.clockOffsetSeconds > 0
                            ? `+${src.clockOffsetSeconds}s (fast)`
                            : src.clockOffsetSeconds < 0
                            ? `${src.clockOffsetSeconds}s (slow)`
                            : '0s (in sync)'}
                        </span>
                      </label>
                      <input
                        type="number"
                        value={src.clockOffsetSeconds}
                        onChange={(e) =>
                          onUpdateSource(src.id, {
                            clockOffsetSeconds: parseInt(e.target.value, 10) || 0,
                          })
                        }
                        placeholder="e.g. 180 or -60"
                        className="w-full bg-slate-950 border border-slate-800 rounded px-2.5 py-1.5 text-xs text-slate-200 font-mono focus:outline-none focus:border-sky-500"
                      />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
};

/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import {
  FileText,
  Activity,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { ForensicTooltip } from './ForensicTooltip';

interface TopStatsBarProps {
  totalEvents: number;
  unparsedCount: number;
  hasTampering: boolean;
  totalSources: number;
  totalFiles: number;
}

export const TopStatsBar: React.FC<TopStatsBarProps> = ({
  totalEvents,
  unparsedCount,
  hasTampering,
  totalSources,
  totalFiles,
}) => {
  // Dynamically computed metrics (zero hardcoded numbers)
  const validEvents = Math.max(0, totalEvents - unparsedCount);
  const accuracyPercentage =
    totalEvents > 0 ? ((validEvents / totalEvents) * 100).toFixed(1) : '100.0';

  return (
    <div className="grid grid-cols-2 sm:grid-cols-2 lg:grid-cols-4 gap-3 mb-4">
      {/* 1. Total Events */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
        <div>
          <div className="text-slate-400 text-[11px] font-medium flex items-center gap-1">
            <span>Total Events</span>
            <ForensicTooltip
              term="Log Events"
              explanation="Every parsed command, login attempt, or web request discovered across all uploaded files."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-slate-100 mt-0.5">
            {totalEvents}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {totalSources} sources · {totalFiles} evidence files
          </div>
        </div>
        <div className="p-2.5 rounded-lg bg-sky-950/60 border border-sky-900/60 text-sky-400">
          <FileText className="w-5 h-5" />
        </div>
      </div>

      {/* 2. Parsing Accuracy */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
        <div>
          <div className="text-slate-400 text-[11px] font-medium flex items-center gap-1">
            <span>Parsing Accuracy</span>
            <ForensicTooltip
              term="Protocol Compliance"
              explanation="Percentage of logs matching strict RFC 3164 or Combined Log syntax. Malformed lines are kept safe as 'unparsed'."
            />
          </div>
          <div className="text-xl font-bold font-mono tabular-nums text-emerald-400 mt-0.5">
            {totalEvents === 0 ? '—' : `${accuracyPercentage}%`}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {unparsedCount} unparsed lines preserved
          </div>
        </div>
        <div className="p-2.5 rounded-lg bg-emerald-950/60 border border-emerald-900/60 text-emerald-400">
          <Activity className="w-5 h-5" />
        </div>
      </div>

      {/* 3. Tampering Alerts */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
        <div>
          <div className="text-slate-400 text-[11px] font-medium flex items-center gap-1">
            <span>Tampering Alerts</span>
            <ForensicTooltip
              term="Digest Verification"
              explanation="Detected SHA-256 hash mismatches in evidence files or broken links in the custody ledger."
            />
          </div>
          <div
            className={`text-xl font-bold font-mono tabular-nums mt-0.5 ${
              hasTampering ? 'text-rose-400' : 'text-slate-200'
            }`}
          >
            {hasTampering ? '1 Violation' : '0 Alerts'}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {hasTampering ? 'Altered byte detected!' : 'Zero hash drift'}
          </div>
        </div>
        <div
          className={`p-2.5 rounded-lg border ${
            hasTampering
              ? 'bg-rose-950/80 border-rose-800 text-rose-400 animate-pulse'
              : 'bg-slate-950 border-slate-800 text-slate-400'
          }`}
        >
          {hasTampering ? (
            <AlertTriangle className="w-5 h-5" />
          ) : (
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
          )}
        </div>
      </div>

      {/* 4. Evidence Integrity Status */}
      <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 flex items-center justify-between">
        <div>
          <div className="text-slate-400 text-[11px] font-medium flex items-center gap-1">
            <span>Custody Status</span>
            <ForensicTooltip
              term="Chain of Custody"
              explanation="Cryptographic state of the ledger. 'Sealed' means all block hashes and previous links are verified intact."
            />
          </div>
          <div
            className={`text-sm font-bold font-mono tracking-tight mt-1 flex items-center gap-1.5 ${
              hasTampering ? 'text-rose-400' : 'text-emerald-400'
            }`}
          >
            {hasTampering ? (
              <>
                <ShieldAlert className="w-4 h-4 shrink-0" />
                TAMPERED / CORRUPTED
              </>
            ) : (
              <>
                <CheckCircle2 className="w-4 h-4 shrink-0" />
                CRYPTO SEALED
              </>
            )}
          </div>
          <div className="text-[10px] text-slate-500 font-mono">
            {hasTampering
              ? 'Run "Verify Integrity" to inspect'
              : 'SHA-256 chain intact'}
          </div>
        </div>
        <div
          className={`p-2.5 rounded-lg border ${
            hasTampering
              ? 'bg-rose-950/60 border-rose-800 text-rose-400'
              : 'bg-emerald-950/60 border-emerald-900/60 text-emerald-400'
          }`}
        >
          {hasTampering ? (
            <ShieldAlert className="w-5 h-5" />
          ) : (
            <ShieldCheck className="w-5 h-5" />
          )}
        </div>
      </div>
    </div>
  );
};

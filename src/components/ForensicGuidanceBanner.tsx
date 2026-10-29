/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  HelpCircle,
  ChevronDown,
  ChevronUp,
  FileText,
  Fingerprint,
  Clock,
  Link,
  Sparkles,
  Rocket,
  ShieldCheck,
} from 'lucide-react';

interface ForensicGuidanceBannerProps {
  onLoadDemoScenario: () => void;
  hasEvents: boolean;
}

export const ForensicGuidanceBanner: React.FC<ForensicGuidanceBannerProps> = ({
  onLoadDemoScenario,
  hasEvents,
}) => {
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-xs mb-4 shadow-sm transition-all">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="p-1.5 rounded bg-sky-950/80 border border-sky-800/80 text-sky-400">
            <HelpCircle className="w-4 h-4" />
          </span>
          <div>
            <span className="font-semibold text-slate-100 text-xs">
              What is CyberTrace? Plain-English Forensics Guide
            </span>
            <span className="text-slate-400 text-[11px] block sm:inline sm:ml-2">
              Built for small IT teams, cybersecurity students, and non-technical stakeholders (PS-013).
            </span>
          </div>
        </div>

        <div className="flex items-center gap-2 shrink-0">
          {!hasEvents && (
            <button
              onClick={onLoadDemoScenario}
              className="flex items-center gap-1.5 px-3 py-1 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded text-xs font-semibold shadow-xs transition-all"
            >
              <Rocket className="w-3.5 h-3.5" />
              <span>Load SSH Demo</span>
            </button>
          )}

          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="flex items-center gap-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs transition-colors"
          >
            <span>{isExpanded ? 'Hide Guide' : 'Explain Concepts'}</span>
            {isExpanded ? (
              <ChevronUp className="w-3.5 h-3.5" />
            ) : (
              <ChevronDown className="w-3.5 h-3.5" />
            )}
          </button>
        </div>
      </div>

      {isExpanded && (
        <div className="mt-3 pt-3 border-t border-slate-800/80 grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3 text-slate-300">
          {/* Concept 1 */}
          <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800 space-y-1">
            <div className="flex items-center gap-1.5 text-sky-400 font-semibold text-xs">
              <FileText className="w-3.5 h-3.5" />
              <span>Log File = Activity Record</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Every time someone visits a website or types a password, computers record a digital footprint. We analyze these traces to piece together incidents.
            </p>
          </div>

          {/* Concept 2 */}
          <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800 space-y-1">
            <div className="flex items-center gap-1.5 text-purple-400 font-semibold text-xs">
              <Fingerprint className="w-3.5 h-3.5" />
              <span>SHA-256 = Digital Fingerprint</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              A 64-character mathematical signature. If even a single letter in the log is changed or deleted, the fingerprint changes, proving tampering!
            </p>
          </div>

          {/* Concept 3 */}
          <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800 space-y-1">
            <div className="flex items-center gap-1.5 text-amber-400 font-semibold text-xs">
              <Clock className="w-3.5 h-3.5" />
              <span>Clock Skew = Time Drift</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Servers often have internal clocks that run 3 minutes fast or slow. Skew correction shifts timestamps so all logs line up in real chronological order.
            </p>
          </div>

          {/* Concept 4 */}
          <div className="bg-slate-950/70 p-2.5 rounded border border-slate-800 space-y-1">
            <div className="flex items-center gap-1.5 text-emerald-400 font-semibold text-xs">
              <Link className="w-3.5 h-3.5" />
              <span>Custody = Tamper-Proof Ledger</span>
            </div>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Every log file is chained to the previous one with cryptographic hashes, creating an unbroken audit trail acceptable for IT compliance.
            </p>
          </div>
        </div>
      )}
    </div>
  );
};

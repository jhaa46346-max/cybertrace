/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { ParsedEvent } from '../types';
import {
  X,
  Copy,
  Check,
  Shield,
  Clock,
  HardDrive,
  FileText,
  User,
  Globe,
  Tag,
  AlertCircle,
} from 'lucide-react';

interface EventDetailDrawerProps {
  event: ParsedEvent | null;
  onClose: () => void;
  showUtc: boolean;
}

export const EventDetailDrawer: React.FC<EventDetailDrawerProps> = ({
  event,
  onClose,
  showUtc,
}) => {
  const [copiedHash, setCopiedHash] = useState(false);
  const [copiedRaw, setCopiedRaw] = useState(false);

  if (!event) return null;

  const copyToClipboard = (text: string, type: 'hash' | 'raw') => {
    navigator.clipboard.writeText(text);
    if (type === 'hash') {
      setCopiedHash(true);
      setTimeout(() => setCopiedHash(false), 2000);
    } else {
      setCopiedRaw(true);
      setTimeout(() => setCopiedRaw(false), 2000);
    }
  };

  return (
    <div className="w-96 border-l border-slate-800 bg-slate-900 flex flex-col h-full text-slate-200 shadow-2xl z-20 overflow-y-auto">
      {/* Header */}
      <div className="flex items-center justify-between p-4 border-b border-slate-800">
        <div className="flex items-center gap-2">
          <Shield className="w-4 h-4 text-sky-400" />
          <h3 className="font-semibold text-sm text-slate-100">
            Forensic Event Detail
          </h3>
        </div>
        <button
          onClick={onClose}
          className="p-1 rounded text-slate-400 hover:text-slate-100 hover:bg-slate-800 transition-colors"
          aria-label="Close detail panel"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-5 text-xs">
        {/* Core Metadata */}
        <div className="space-y-2">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Evidence Provenance
          </div>
          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <HardDrive className="w-3.5 h-3.5 text-slate-500" /> Source Host
              </span>
              <span className="font-mono text-sky-400 font-medium">
                {event.host}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <FileText className="w-3.5 h-3.5 text-slate-500" /> File & Line
              </span>
              <span className="font-mono text-slate-200">
                {event.raw_ref.fileName} : L#{event.raw_ref.lineNumber}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Tag className="w-3.5 h-3.5 text-slate-500" /> Event Category
              </span>
              <span className="font-mono capitalize text-slate-300">
                {event.event_type.replace('_', ' ')}
              </span>
            </div>
          </div>
        </div>

        {/* Timestamps & Derivation Breakdown */}
        <div className="space-y-2">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Timestamp Resolution
          </div>
          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/80 space-y-2">
            <div>
              <div className="text-slate-400 text-[10px] mb-0.5">Original Log String</div>
              <div className="font-mono text-amber-300/90 bg-slate-900 px-2 py-1 rounded border border-slate-800 select-all">
                {event.original_timestamp}
              </div>
            </div>
            <div>
              <div className="text-slate-400 text-[10px] mb-0.5">Normalized UTC Timestamp</div>
              <div className="font-mono text-emerald-400 bg-slate-900 px-2 py-1 rounded border border-slate-800 select-all">
                {event.normalized_utc}
              </div>
            </div>
            <div className="pt-1 border-t border-slate-800/80">
              <div className="text-slate-400 text-[10px] mb-1">Normalization Derivation Notes</div>
              <div className="text-[11px] text-slate-300 leading-relaxed font-mono bg-slate-900/50 p-2 rounded border border-slate-800">
                {event.normalization_notes}
              </div>
            </div>
            <div className="flex items-center justify-between text-[11px] text-slate-400 pt-1">
              <span>Timestamp Confidence:</span>
              <span className="font-mono uppercase text-sky-400 font-semibold">
                {event.confidence}
              </span>
            </div>
          </div>
        </div>

        {/* Parsed Entities */}
        <div className="space-y-2">
          <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
            Identified Principals
          </div>
          <div className="bg-slate-950/60 p-3 rounded border border-slate-800/80 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <User className="w-3.5 h-3.5 text-slate-500" /> Target User
              </span>
              <span className="font-mono text-amber-300 font-medium">
                {event.user || 'None extracted'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-slate-500" /> Source IP
              </span>
              <span className="font-mono text-purple-300 font-medium">
                {event.src_ip || 'None extracted'}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-slate-500" /> Service Daemon
              </span>
              <span className="font-mono text-slate-200">
                {event.service}
              </span>
            </div>
          </div>
        </div>

        {/* Cryptographic Line Verification */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Line SHA-256 Digest
            </span>
            <button
              onClick={() => copyToClipboard(event.raw_ref.lineHash, 'hash')}
              className="text-[10px] text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
            >
              {copiedHash ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" /> Copy Hash
                </>
              )}
            </button>
          </div>
          <div className="p-2 bg-slate-950 rounded border border-slate-800 font-mono text-[10px] text-slate-400 break-all select-all">
            {event.raw_ref.lineHash || 'No line hash computed'}
          </div>
        </div>

        {/* Raw Preserved Line Content */}
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
              Untouched Raw Log Line
            </span>
            <button
              onClick={() => copyToClipboard(event.raw_ref.rawText, 'raw')}
              className="text-[10px] text-sky-400 hover:text-sky-300 flex items-center gap-1 transition-colors"
            >
              {copiedRaw ? (
                <>
                  <Check className="w-3 h-3 text-emerald-400" /> Copied
                </>
              ) : (
                <>
                  <Copy className="w-3 h-3" /> Copy Line
                </>
              )}
            </button>
          </div>
          <div className="p-3 bg-slate-950 rounded border border-slate-800 font-mono text-slate-200 text-xs whitespace-pre-wrap break-all leading-relaxed select-all">
            {event.raw_ref.rawText}
          </div>
          <p className="text-[10px] text-slate-500">
            Escaped and rendered read-only. Original byte sequences are preserved without alteration.
          </p>
        </div>
      </div>
    </div>
  );
};

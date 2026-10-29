/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import {
  CustodyLedgerEntry,
  EvidenceFile,
  IntegrityReport,
} from '../types';
import {
  ShieldCheck,
  ShieldAlert,
  Link,
  Copy,
  Check,
  RotateCcw,
  AlertTriangle,
  FileText,
  Lock,
  Unlock,
  CheckCircle2,
  Fingerprint,
} from 'lucide-react';
import { ForensicTooltip } from '../components/ForensicTooltip';

interface EvidenceViewProps {
  ledger: CustodyLedgerEntry[];
  evidenceFiles: EvidenceFile[];
  onVerifyIntegrity: () => Promise<IntegrityReport>;
  onSimulateTampering: () => void;
  onRestoreCleanState: () => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({
  ledger,
  evidenceFiles,
  onVerifyIntegrity,
  onSimulateTampering,
  onRestoreCleanState,
}) => {
  const [report, setReport] = useState<IntegrityReport | null>(null);
  const [isVerifying, setIsVerifying] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const handleVerify = async () => {
    setIsVerifying(true);
    const res = await onVerifyIntegrity();
    setReport(res);
    setIsVerifying(false);
  };

  const copyHash = (hash: string) => {
    navigator.clipboard.writeText(hash);
    setCopiedHash(hash);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const hasTampering =
    evidenceFiles.some((f) => f.isTampered) || ledger.some((l) => l.tampered);

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Lock className="w-5 h-5 text-sky-400" />
            Evidence Security & Chain of Custody
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Native SHA-256 cryptographic hashing (Web Crypto API) and tamper-evident hash-chained custody ledger.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {hasTampering && (
            <button
              onClick={onRestoreCleanState}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium border border-slate-700 transition-colors cursor-pointer"
            >
              <RotateCcw className="w-3.5 h-3.5" /> Restore Pristine Evidence
            </button>
          )}

          <button
            onClick={onSimulateTampering}
            disabled={evidenceFiles.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-950/80 hover:bg-rose-900 border border-rose-800/80 text-rose-200 disabled:opacity-40 rounded text-xs font-semibold transition-colors cursor-pointer shadow-xs"
          >
            <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
            <span>⚠️ Simulate File Tampering</span>
          </button>

          <button
            onClick={handleVerify}
            disabled={isVerifying || evidenceFiles.length === 0}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 text-white rounded text-xs font-semibold shadow-xs transition-colors cursor-pointer"
          >
            <ShieldCheck className="w-4 h-4" />
            <span>{isVerifying ? 'Re-calculating Hashes...' : '🛡️ Verify Evidence Integrity'}</span>
          </button>
        </div>
      </div>

      {/* Integrity Verification Alert Banner */}
      {report && (
        <div
          className={`p-4 rounded-lg border flex flex-col gap-2 ${
            report.allValid
              ? 'bg-emerald-950/40 border-emerald-800/80 text-emerald-200'
              : 'bg-rose-950/60 border-rose-800 text-rose-200'
          }`}
        >
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 font-semibold text-sm">
              {report.allValid ? (
                <>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  All Evidence Digests & Chain of Custody Verified (Zero Discrepancies)
                </>
              ) : (
                <>
                  <ShieldAlert className="w-5 h-5 text-rose-400 animate-bounce" />
                  Cryptographic Integrity Failure Detected! Evidence was modified.
                </>
              )}
            </div>
            <span className="text-[11px] font-mono opacity-80">
              Verified at {report.timestamp.replace('T', ' ').slice(0, 19)} UTC
            </span>
          </div>

          <div className="text-xs space-y-1">
            <p>
              Re-calculated SHA-256 digests across {report.totalFiles} evidence file(s) and all constituent lines.
              Ledger chain status: {report.ledgerValid ? 'INTACT' : 'CORRUPTED/BROKEN'}.
            </p>

            {report.tamperedItems.length > 0 && (
              <div className="mt-3 space-y-2 bg-slate-950/90 p-3.5 rounded border border-rose-900/80 font-mono text-[11px]">
                <div className="font-bold text-rose-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-4 h-4" /> TAMPERING DETECTION LOG:
                </div>
                {report.tamperedItems.map((item, idx) => (
                  <div key={idx} className="border-t border-rose-950 pt-2 space-y-1">
                    <div className="text-rose-300 font-semibold">{item.details}</div>
                    <div className="text-slate-400">
                      Expected Hash: <span className="text-emerald-400 break-all">{item.expectedHash}</span>
                    </div>
                    <div className="text-slate-400">
                      Actual Hash: <span className="text-rose-400 break-all">{item.actualHash}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Stored Evidence Files Table */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center justify-between">
          <span className="flex items-center gap-1.5">
            <Fingerprint className="w-4 h-4 text-sky-400" />
            Acquired Evidence Files ({evidenceFiles.length})
            <ForensicTooltip
              term="SHA-256 Files"
              explanation="Each file is stored in its original untouched form with a file-level and line-level SHA-256 fingerprint."
            />
          </span>
          <span className="text-xs text-slate-400">
            Read-only content with line-by-line cryptographic indices
          </span>
        </h3>

        {evidenceFiles.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/40 rounded-lg border border-slate-800 text-slate-400 text-xs">
            No evidence files ingested yet.
          </div>
        ) : (
          <div className="border border-slate-800 rounded-lg overflow-hidden bg-slate-900/80">
            <table className="w-full text-left text-xs border-collapse">
              <thead>
                <tr className="border-b border-slate-800 bg-slate-950 text-slate-400 font-medium">
                  <th className="p-3">Filename</th>
                  <th className="p-3">Size</th>
                  <th className="p-3">Lines</th>
                  <th className="p-3">File SHA-256 Digest</th>
                  <th className="p-3">Acquisition UTC</th>
                  <th className="p-3 text-right">Integrity</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono text-slate-300">
                {evidenceFiles.map((file) => (
                  <tr
                    key={file.id}
                    className={`hover:bg-slate-800/40 transition-colors ${
                      file.isTampered ? 'bg-rose-950/40 text-rose-200' : ''
                    }`}
                  >
                    <td className="p-3 font-semibold text-slate-100 flex items-center gap-2">
                      <FileText className="w-3.5 h-3.5 text-sky-400" />
                      {file.name}
                    </td>
                    <td className="p-3 tabular-nums">
                      {(file.sizeBytes / 1024).toFixed(2)} KB
                    </td>
                    <td className="p-3 tabular-nums">{file.lineHashes.length}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2 max-w-xs">
                        <span className="truncate text-slate-400 text-[11px]">
                          {file.sha256}
                        </span>
                        <button
                          onClick={() => copyHash(file.sha256)}
                          className="text-slate-500 hover:text-slate-300 transition-colors shrink-0 cursor-pointer"
                          title="Copy SHA-256"
                        >
                          {copiedHash === file.sha256 ? (
                            <Check className="w-3.5 h-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="w-3.5 h-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                    <td className="p-3 text-slate-400 text-[11px]">
                      {file.uploadedAtUtc.replace('T', ' ').slice(0, 19)}
                    </td>
                    <td className="p-3 text-right">
                      {file.isTampered ? (
                        <span className="text-rose-400 font-bold text-[11px] flex items-center justify-end gap-1">
                          <ShieldAlert className="w-3.5 h-3.5" /> TAMPERED
                        </span>
                      ) : (
                        <span className="text-emerald-400 text-[11px] flex items-center justify-end gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Verified Pristine
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Hash-Chained Custody Ledger */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-slate-200 flex items-center justify-between">
          <span className="flex items-center gap-2">
            <Link className="w-4 h-4 text-purple-400" />
            Hash-Chained Custody Ledger ({ledger.length} Blocks)
            <ForensicTooltip
              term="Custody Blocks"
              explanation="Each block mathematically seals: BlockIndex | FileId | Name | Size | SHA-256 | UTC | Examiner | Host | PrevHash"
            />
          </span>
          <span className="text-xs text-slate-400">
            Cryptographic block linking ensures evidence cannot be inserted or omitted
          </span>
        </h3>

        {ledger.length === 0 ? (
          <div className="p-8 text-center bg-slate-900/40 rounded-lg border border-slate-800 text-slate-400 text-xs">
            No custody ledger entries recorded.
          </div>
        ) : (
          <div className="space-y-3">
            {ledger.map((block) => (
              <div
                key={block.blockIndex}
                className={`bg-slate-900 border rounded-lg p-4 font-mono text-xs space-y-3 transition-colors ${
                  block.tampered
                    ? 'border-rose-800 bg-rose-950/30'
                    : 'border-slate-800'
                }`}
              >
                {/* Block Title Bar */}
                <div className="flex items-center justify-between pb-2 border-b border-slate-800 text-slate-300">
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 font-bold">
                      BLOCK #{block.blockIndex}
                    </span>
                    <span className="text-slate-100 font-semibold font-sans">
                      {block.fileName}
                    </span>
                    <span className="text-slate-500 font-sans">
                      ({(block.fileSizeBytes / 1024).toFixed(1)} KB)
                    </span>
                  </div>

                  <div className="text-slate-400 text-[11px] font-sans">
                    Collected: {block.utcCollectionTime.replace('T', ' ').slice(0, 19)} UTC · Examiner:{' '}
                    <span className="text-slate-200 font-mono">{block.examinerName}</span>
                  </div>
                </div>

                {/* Hashes Row */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-[11px]">
                  <div>
                    <div className="text-slate-500 mb-0.5 flex items-center justify-between">
                      <span>PREVIOUS BLOCK LINK HASH</span>
                      {block.blockIndex === 0 && (
                        <span className="text-purple-400 font-sans text-[10px]">
                          Genesis Block
                        </span>
                      )}
                    </div>
                    <div className="bg-slate-950 p-2 rounded border border-slate-800 text-slate-400 break-all select-all">
                      {block.previousEntryHash}
                    </div>
                  </div>

                  <div>
                    <div className="text-slate-500 mb-0.5 flex items-center justify-between">
                      <span>CALCULATED BLOCK HASH</span>
                      <button
                        onClick={() => copyHash(block.blockHash)}
                        className="text-slate-500 hover:text-slate-300 font-sans text-[10px] flex items-center gap-1 cursor-pointer"
                      >
                        {copiedHash === block.blockHash ? 'Copied' : 'Copy'}
                      </button>
                    </div>
                    <div
                      className={`p-2 rounded border break-all select-all ${
                        block.tampered
                          ? 'bg-rose-950/80 border-rose-800 text-rose-300 font-bold'
                          : 'bg-slate-950 border-slate-800 text-sky-400'
                      }`}
                    >
                      {block.blockHash}
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

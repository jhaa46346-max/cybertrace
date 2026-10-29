/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CustodyLedgerEntry,
  EvidenceFile,
  IntegrityReport,
  LogSource,
} from '../types';
import {
  sha256Text,
  hashFileLines,
  calculateLedgerBlockHash,
  verifyCustodyChain,
} from './crypto';

/**
 * Creates an EvidenceFile record from raw file content.
 * Stores original content untouched, computes file-level SHA-256 and line-level SHA-256.
 */
export async function createEvidenceRecord(
  file: File | { name: string; content: string },
  assignedSourceId?: string
): Promise<{ evidence: EvidenceFile; lineHashes: string[] }> {
  let name: string;
  let rawContent: string;
  let sizeBytes: number;

  if (file instanceof File) {
    name = file.name;
    rawContent = await file.text();
    sizeBytes = file.size;
  } else {
    name = file.name;
    rawContent = file.content;
    sizeBytes = new TextEncoder().encode(rawContent).length;
  }

  const sha256 = await sha256Text(rawContent);
  const lines = rawContent.split(/\r?\n/);
  const lineHashes = await hashFileLines(lines);

  const evidence: EvidenceFile = {
    id: `ev-file-${Date.now()}-${Math.random().toString(36).substring(2, 7)}`,
    name,
    sizeBytes,
    sha256,
    lineHashes,
    rawContent,
    uploadedAtUtc: new Date().toISOString(),
    assignedSourceId,
    isTampered: false,
  };

  return { evidence, lineHashes };
}

/**
 * Appends a new verified entry to the hash-chained custody ledger.
 */
export async function appendToCustodyLedger(
  currentLedger: CustodyLedgerEntry[],
  evidence: EvidenceFile,
  examinerName: string,
  sourceHost: string
): Promise<CustodyLedgerEntry> {
  const blockIndex = currentLedger.length;
  const previousEntryHash =
    blockIndex === 0 ? '0'.repeat(64) : currentLedger[blockIndex - 1].blockHash;

  const draftEntry: Omit<CustodyLedgerEntry, 'blockHash'> = {
    blockIndex,
    fileId: evidence.id,
    fileName: evidence.name,
    fileSizeBytes: evidence.sizeBytes,
    fileSha256: evidence.sha256,
    utcCollectionTime: new Date().toISOString(),
    examinerName: examinerName || 'Examiner (Small IT Team)',
    sourceHost: sourceHost || 'unknown-host',
    previousEntryHash,
  };

  const blockHash = await calculateLedgerBlockHash(draftEntry);

  return {
    ...draftEntry,
    blockHash,
    tampered: false,
  };
}

/**
 * Re-hashes every file and line, checks cryptographic ledger hashes, and reports any discrepancies.
 */
export async function verifyAllIntegrity(
  evidenceFiles: EvidenceFile[],
  ledger: CustodyLedgerEntry[]
): Promise<IntegrityReport> {
  const tamperedItems: IntegrityReport['tamperedItems'] = [];
  let filesPassed = 0;
  let filesFailed = 0;

  for (const file of evidenceFiles) {
    // Re-hash full file
    const currentSha256 = await sha256Text(file.rawContent);
    if (currentSha256 !== file.sha256) {
      filesFailed++;
      tamperedItems.push({
        type: 'file',
        id: file.id,
        details: `File "${file.name}" SHA-256 digest mismatch. File content has been modified since acquisition!`,
        expectedHash: file.sha256,
        actualHash: currentSha256,
      });
    } else {
      filesPassed++;
    }

    // Verify lines
    const lines = file.rawContent.split(/\r?\n/);
    if (lines.length !== file.lineHashes.length) {
      tamperedItems.push({
        type: 'line',
        id: `${file.id}-line-count`,
        details: `Line count discrepancy in "${file.name}": expected ${file.lineHashes.length} lines, found ${lines.length}.`,
        expectedHash: `${file.lineHashes.length} lines`,
        actualHash: `${lines.length} lines`,
      });
    } else {
      for (let l = 0; l < lines.length; l++) {
        const recomputedLineHash = await sha256Text(lines[l]);
        if (recomputedLineHash !== file.lineHashes[l]) {
          tamperedItems.push({
            type: 'line',
            id: `${file.id}-line-${l + 1}`,
            details: `Line #${l + 1} in "${file.name}" hash mismatch. Text was altered!`,
            expectedHash: file.lineHashes[l],
            actualHash: recomputedLineHash,
          });
          break; // Report first line mismatch per file to avoid flood
        }
      }
    }
  }

  // Verify Ledger hash chain
  const chainCheck = await verifyCustodyChain(ledger);
  let ledgerValid = chainCheck.isValid;

  if (!ledgerValid && chainCheck.brokenAtIndex !== null) {
    const brokenEntry = ledger[chainCheck.brokenAtIndex];
    tamperedItems.push({
      type: 'ledger',
      id: `ledger-block-${brokenEntry.blockIndex}`,
      details: `Custody ledger chain broken at block #${brokenEntry.blockIndex} ("${brokenEntry.fileName}"). Previous link hash or block hash does not match computed value!`,
      expectedHash: 'Valid cryptographic link',
      actualHash: 'BROKEN_CHAIN',
    });
  }

  return {
    timestamp: new Date().toISOString(),
    allValid: tamperedItems.length === 0,
    totalFiles: evidenceFiles.length,
    filesPassed,
    filesFailed,
    ledgerValid,
    tamperedItems,
  };
}

/**
 * Simulates tampering by modifying a single byte/string in the target evidence file content,
 * or altering a ledger block hash to demonstrate cryptographic detection.
 */
export function simulateTamperingOnFile(file: EvidenceFile): EvidenceFile {
  const lines = file.rawContent.split(/\r?\n/);
  if (lines.length === 0) return file;

  // Alter line 2 (or line 0 if only 1 line)
  const targetIndex = Math.min(1, lines.length - 1);
  lines[targetIndex] = lines[targetIndex] + ' [TAMPERED_INJECTED_PAYLOAD]';

  return {
    ...file,
    rawContent: lines.join('\n'),
    isTampered: true,
  };
}

/**
 * Simulates tampering with the custody ledger block hash.
 */
export function simulateTamperingOnLedger(
  ledger: CustodyLedgerEntry[]
): CustodyLedgerEntry[] {
  if (ledger.length === 0) return ledger;
  return ledger.map((entry, index) => {
    if (index === 0) {
      // Modify blockHash
      return {
        ...entry,
        blockHash: 'deadbeef' + entry.blockHash.slice(8),
        tampered: true,
      };
    }
    return entry;
  });
}

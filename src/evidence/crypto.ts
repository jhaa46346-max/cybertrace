/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { CustodyLedgerEntry } from '../types';

/**
 * Computes SHA-256 hash using the standard Web Crypto API.
 * 100% client-side, zero external cryptography dependencies.
 */
export async function sha256Text(text: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

export async function sha256Buffer(buffer: ArrayBuffer): Promise<string> {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Compute SHA-256 hash for every line in a file for line-level forensics.
 */
export async function hashFileLines(lines: string[]): Promise<string[]> {
  const hashes: string[] = [];
  for (const line of lines) {
    hashes.push(await sha256Text(line));
  }
  return hashes;
}

/**
 * Calculates cryptographic block hash for a custody ledger entry.
 * Hash is composed of: blockIndex | fileId | fileName | fileSizeBytes | fileSha256 | utcCollectionTime | examinerName | sourceHost | previousEntryHash
 */
export async function calculateLedgerBlockHash(
  entry: Omit<CustodyLedgerEntry, 'blockHash' | 'tampered'>
): Promise<string> {
  const payload = [
    entry.blockIndex,
    entry.fileId,
    entry.fileName,
    entry.fileSizeBytes,
    entry.fileSha256,
    entry.utcCollectionTime,
    entry.examinerName,
    entry.sourceHost,
    entry.previousEntryHash,
  ].join('|');
  return sha256Text(payload);
}

/**
 * Verifies that the custody ledger's hash chain is intact and untampered.
 */
export async function verifyCustodyChain(
  ledger: CustodyLedgerEntry[]
): Promise<{ isValid: boolean; brokenAtIndex: number | null }> {
  if (ledger.length === 0) {
    return { isValid: true, brokenAtIndex: null };
  }

  let expectedPrevHash = '0'.repeat(64); // Genesis previous hash

  for (let i = 0; i < ledger.length; i++) {
    const entry = ledger[i];

    // Check previous hash link
    if (entry.previousEntryHash !== expectedPrevHash) {
      return { isValid: false, brokenAtIndex: i };
    }

    // Check block hash computation
    const recomputedBlockHash = await calculateLedgerBlockHash(entry);
    if (entry.blockHash !== recomputedBlockHash) {
      return { isValid: false, brokenAtIndex: i };
    }

    expectedPrevHash = entry.blockHash;
  }

  return { isValid: true, brokenAtIndex: null };
}

/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import {
  CaseMetadata,
  CustodyLedgerEntry,
  EvidenceFile,
  LogSource,
  ParsedEvent,
  AITriageRule,
} from '../types';

const DB_NAME = 'CyberTrace_Forensics_DB';
const DB_VERSION = 1;

function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    if (!window.indexedDB) {
      reject(new Error('IndexedDB not supported in this environment'));
      return;
    }

    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;

      if (!db.objectStoreNames.contains('cases')) {
        db.createObjectStore('cases', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('sources')) {
        db.createObjectStore('sources', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('evidence')) {
        db.createObjectStore('evidence', { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains('ledger')) {
        db.createObjectStore('ledger', { keyPath: 'blockIndex' });
      }
      if (!db.objectStoreNames.contains('events')) {
        const eventStore = db.createObjectStore('events', { keyPath: 'id' });
        eventStore.createIndex('normalized_utc', 'normalized_utc', { unique: false });
        eventStore.createIndex('event_type', 'event_type', { unique: false });
      }
      if (!db.objectStoreNames.contains('ai_rules')) {
        db.createObjectStore('ai_rules', { keyPath: 'id' });
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Generic store helpers
async function putItem<T>(storeName: string, item: T): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const req = store.put(item);
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

async function putItems<T>(storeName: string, items: T[]): Promise<void> {
  if (items.length === 0) return;
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    for (const item of items) {
      store.put(item);
    }
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function getAllItems<T>(storeName: string): Promise<T[]> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const req = store.getAll();
    req.onsuccess = () => resolve(req.result as T[]);
    req.onerror = () => reject(req.error);
  });
}

async function clearStore(storeName: string): Promise<void> {
  const db = await openDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    const store = tx.objectStore(storeName);
    const req = store.clear();
    req.onsuccess = () => resolve();
    req.onerror = () => reject(req.error);
  });
}

export const forensicStorage = {
  // Case Metadata
  saveCase: async (caseData: CaseMetadata) => putItem('cases', caseData),
  getCases: async (): Promise<CaseMetadata[]> => getAllItems<CaseMetadata>('cases'),

  // Sources
  saveSource: async (source: LogSource) => putItem('sources', source),
  saveSources: async (sources: LogSource[]) => putItems('sources', sources),
  getSources: async (): Promise<LogSource[]> => getAllItems<LogSource>('sources'),

  // Evidence Files
  saveEvidenceFile: async (evidence: EvidenceFile) => putItem('evidence', evidence),
  saveEvidenceFiles: async (files: EvidenceFile[]) => putItems('evidence', files),
  getEvidenceFiles: async (): Promise<EvidenceFile[]> =>
    getAllItems<EvidenceFile>('evidence'),

  // Custody Ledger
  saveLedger: async (ledger: CustodyLedgerEntry[]) => {
    await clearStore('ledger');
    await putItems('ledger', ledger);
  },
  getLedger: async (): Promise<CustodyLedgerEntry[]> =>
    getAllItems<CustodyLedgerEntry>('ledger'),

  // Events
  saveEvents: async (events: ParsedEvent[]) => {
    await clearStore('events');
    await putItems('events', events);
  },
  getEvents: async (): Promise<ParsedEvent[]> => getAllItems<ParsedEvent>('events'),

  // AI Triage Rules
  saveRules: async (rules: AITriageRule[]) => {
    await clearStore('ai_rules');
    await putItems('ai_rules', rules);
  },
  getRules: async (): Promise<AITriageRule[]> => getAllItems<AITriageRule>('ai_rules'),

  // Full reset
  clearAll: async () => {
    await clearStore('cases');
    await clearStore('sources');
    await clearStore('evidence');
    await clearStore('ledger');
    await clearStore('events');
    await clearStore('ai_rules');
  },
};

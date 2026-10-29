/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useCallback } from 'react';
import {
  CaseMetadata,
  CustodyLedgerEntry,
  EvidenceFile,
  LogSource,
  ParsedEvent,
  AITriageRule,
} from './types';
import {
  SCENARIO_1_CASE,
  SCENARIO_1_SOURCES,
  SCENARIO_1_AUTH_LOG,
  SCENARIO_1_WEB_LOG,
} from './scenario/sshBruteForceScenario';
import { forensicStorage } from './storage/db';
import {
  createEvidenceRecord,
  appendToCustodyLedger,
  verifyAllIntegrity,
  simulateTamperingOnFile,
} from './evidence/custody';
import { parseLogFile, autoDetectFormat } from './parsers';
import { DEFAULT_TRIAGE_RULES } from './ai/forensicRules';

import { CaseView } from './views/CaseView';
import { SourcesView } from './views/SourcesView';
import { EvidenceView } from './views/EvidenceView';
import { TimelineView } from './views/TimelineView';
import { TopStatsBar } from './components/TopStatsBar';
import { ForensicGuidanceBanner } from './components/ForensicGuidanceBanner';

import {
  FolderKanban,
  Layers,
  Shield,
  Clock,
  RotateCcw,
  Rocket,
  HelpCircle,
} from 'lucide-react';

type NavTab = 'case' | 'sources' | 'evidence' | 'timeline';

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>('timeline');
  const [caseData, setCaseData] = useState<CaseMetadata>(SCENARIO_1_CASE);
  const [sources, setSources] = useState<LogSource[]>([]);
  const [evidenceFiles, setEvidenceFiles] = useState<EvidenceFile[]>([]);
  const [ledger, setLedger] = useState<CustodyLedgerEntry[]>([]);
  const [events, setEvents] = useState<ParsedEvent[]>([]);
  const [rules, setRules] = useState<AITriageRule[]>(DEFAULT_TRIAGE_RULES);
  const [showUtc, setShowUtc] = useState<boolean>(true);
  const [isLoading, setIsLoading] = useState<boolean>(true);

  // Re-parse all events from current sources and stored evidence files
  const reparseAllSources = useCallback(
    (
      currentSources: LogSource[],
      currentEvidence: EvidenceFile[],
      currentCase: CaseMetadata
    ): ParsedEvent[] => {
      const allEvents: ParsedEvent[] = [];

      for (const src of currentSources) {
        const file = currentEvidence.find((f) => f.id === src.fileId);
        if (!file) continue;

        const parsed = parseLogFile(file.rawContent, file.lineHashes, src, {
          referenceDateIso: currentCase.referenceDate,
          defaultHostLabel: src.hostLabel,
        });

        src.eventCount = parsed.length;
        src.unparsedCount = parsed.filter((e) => e.event_type === 'unparsed').length;

        allEvents.push(...parsed);
      }

      // Sort unified events strictly chronologically by normalized UTC
      allEvents.sort(
        (a, b) =>
          new Date(a.normalized_utc).getTime() -
          new Date(b.normalized_utc).getTime()
      );

      return allEvents;
    },
    []
  );

  // Load Built-in Scenario 1 "SSH Brute Force"
  const loadScenario1 = useCallback(async () => {
    setIsLoading(true);

    const initialCase = { ...SCENARIO_1_CASE };
    setCaseData(initialCase);
    await forensicStorage.saveCase(initialCase);

    // Create Evidence Record 1: auth.log
    const { evidence: authEv } = await createEvidenceRecord({
      name: 'auth.log',
      content: SCENARIO_1_AUTH_LOG,
    });

    // Create Evidence Record 2: access.log
    const { evidence: webEv } = await createEvidenceRecord({
      name: 'access.log',
      content: SCENARIO_1_WEB_LOG,
    });

    const newEvidenceFiles = [authEv, webEv];
    setEvidenceFiles(newEvidenceFiles);
    await forensicStorage.saveEvidenceFiles(newEvidenceFiles);

    // Custody ledger hash chaining
    const ledgerEntry1 = await appendToCustodyLedger(
      [],
      authEv,
      initialCase.investigator,
      'srv-prod-auth'
    );
    const ledgerEntry2 = await appendToCustodyLedger(
      [ledgerEntry1],
      webEv,
      initialCase.investigator,
      'srv-prod-web'
    );
    const newLedger = [ledgerEntry1, ledgerEntry2];
    setLedger(newLedger);
    await forensicStorage.saveLedger(newLedger);

    // Sources
    const newSources: LogSource[] = [
      {
        ...SCENARIO_1_SOURCES[0],
        fileId: authEv.id,
        fileName: authEv.name,
      },
      {
        ...SCENARIO_1_SOURCES[1],
        fileId: webEv.id,
        fileName: webEv.name,
      },
    ];

    // Parse events
    const parsed = reparseAllSources(newSources, newEvidenceFiles, initialCase);

    setSources(newSources);
    setEvents(parsed);
    await forensicStorage.saveSources(newSources);
    await forensicStorage.saveEvents(parsed);

    // AI rules
    setRules(DEFAULT_TRIAGE_RULES);
    await forensicStorage.saveRules(DEFAULT_TRIAGE_RULES);

    setIsLoading(false);
  }, [reparseAllSources]);

  // Initial load from IndexedDB
  useEffect(() => {
    async function init() {
      try {
        const storedCases = await forensicStorage.getCases();
        const storedSources = await forensicStorage.getSources();
        const storedEvidence = await forensicStorage.getEvidenceFiles();
        const storedLedger = await forensicStorage.getLedger();
        const storedRules = await forensicStorage.getRules();

        if (storedCases.length > 0 && storedSources.length > 0) {
          setCaseData(storedCases[0]);
          setSources(storedSources);
          setEvidenceFiles(storedEvidence);
          setLedger(storedLedger);
          if (storedRules.length > 0) {
            setRules(storedRules);
          }

          // Re-parse to guarantee in-memory consistency
          const parsed = reparseAllSources(
            storedSources,
            storedEvidence,
            storedCases[0]
          );
          setEvents(parsed);
          setIsLoading(false);
        } else {
          // Initialize with Scenario 1
          await loadScenario1();
        }
      } catch (err) {
        console.warn('Database initialization warning, loading demo scenario:', err);
        await loadScenario1();
      }
    }

    init();
  }, [loadScenario1, reparseAllSources]);

  // Handle file uploads (multiple drag-and-drop)
  const handleAddFiles = async (files: File[]) => {
    setIsLoading(true);
    const updatedEvidence = [...evidenceFiles];
    let updatedLedger = [...ledger];
    const newSources: LogSource[] = [...sources];

    for (const file of files) {
      const { evidence } = await createEvidenceRecord(file);
      updatedEvidence.push(evidence);

      // Add to custody ledger
      const newBlock = await appendToCustodyLedger(
        updatedLedger,
        evidence,
        caseData.investigator,
        'unassigned-host'
      );
      updatedLedger.push(newBlock);

      // Auto detect format from lines
      const sampleLines = evidence.rawContent.split(/\r?\n/).slice(0, 15);
      const detectedFormat = autoDetectFormat(sampleLines);

      // Auto configure source
      const newSource: LogSource = {
        id: `src-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
        name: file.name.replace(/\.[^/.]+$/, '').replace(/[-_]/g, ' '),
        hostLabel: file.name.includes('web')
          ? 'srv-web'
          : file.name.includes('auth')
          ? 'srv-auth'
          : 'srv-host-01',
        format: detectedFormat,
        timezone: 'UTC',
        clockOffsetSeconds: 0,
        fileId: evidence.id,
        fileName: file.name,
      };
      newSources.push(newSource);
    }

    const recomputedEvents = reparseAllSources(
      newSources,
      updatedEvidence,
      caseData
    );

    setEvidenceFiles(updatedEvidence);
    setLedger(updatedLedger);
    setSources(newSources);
    setEvents(recomputedEvents);

    await forensicStorage.saveEvidenceFiles(updatedEvidence);
    await forensicStorage.saveLedger(updatedLedger);
    await forensicStorage.saveSources(newSources);
    await forensicStorage.saveEvents(recomputedEvents);

    setIsLoading(false);
  };

  // Update source configuration (e.g. timezone or offset)
  const handleUpdateSource = async (
    sourceId: string,
    updates: Partial<LogSource>
  ) => {
    const updatedSources = sources.map((s) =>
      s.id === sourceId ? { ...s, ...updates } : s
    );
    const recomputedEvents = reparseAllSources(
      updatedSources,
      evidenceFiles,
      caseData
    );

    setSources(updatedSources);
    setEvents(recomputedEvents);
    await forensicStorage.saveSources(updatedSources);
    await forensicStorage.saveEvents(recomputedEvents);
  };

  // Delete source
  const handleDeleteSource = async (sourceId: string) => {
    const updatedSources = sources.filter((s) => s.id !== sourceId);
    const recomputedEvents = reparseAllSources(
      updatedSources,
      evidenceFiles,
      caseData
    );

    setSources(updatedSources);
    setEvents(recomputedEvents);
    await forensicStorage.saveSources(updatedSources);
    await forensicStorage.saveEvents(recomputedEvents);
  };

  // Update Case Metadata
  const handleUpdateCase = async (updated: Partial<CaseMetadata>) => {
    const newCase = {
      ...caseData,
      ...updated,
      updatedAtUtc: new Date().toISOString(),
    };
    setCaseData(newCase);
    await forensicStorage.saveCase(newCase);

    // If referenceDate changed, reparse syslog
    if (updated.referenceDate && updated.referenceDate !== caseData.referenceDate) {
      const recomputed = reparseAllSources(sources, evidenceFiles, newCase);
      setEvents(recomputed);
      await forensicStorage.saveEvents(recomputed);
    }
  };

  // Verify integrity
  const handleVerifyIntegrity = async () => {
    return verifyAllIntegrity(evidenceFiles, ledger);
  };

  // Simulate tampering
  const handleSimulateTampering = () => {
    if (evidenceFiles.length === 0) return;
    const tamperedFile = simulateTamperingOnFile(evidenceFiles[0]);
    const updated = [tamperedFile, ...evidenceFiles.slice(1)];
    setEvidenceFiles(updated);

    // Also re-parse to reflect tampered line
    const recomputed = reparseAllSources(sources, updated, caseData);
    setEvents(recomputed);
  };

  // Restore pristine state
  const handleRestoreCleanState = async () => {
    await loadScenario1();
  };

  // Dynamically calculate metrics for overview
  const unparsedCount = events.filter((e) => e.event_type === 'unparsed').length;
  const hasTampering =
    evidenceFiles.some((f) => f.isTampered) || ledger.some((l) => l.tampered);

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-slate-950 text-slate-100 font-sans antialiased">
      {/* Simplified 4-Section Sidebar Navigation */}
      <aside className="w-64 shrink-0 bg-slate-900 border-r border-slate-800 flex flex-col justify-between select-none">
        <div>
          {/* Brand Wordmark (Clean display structure without decorative pills) */}
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-sky-400" />
              <span className="font-bold text-base tracking-tight text-slate-100">
                CyberTrace
              </span>
            </div>
            <span className="text-[10px] font-mono text-slate-400 uppercase bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800">
              PS-013 DFIR
            </span>
          </div>

          {/* 4 Core Navigation Sections */}
          <nav className="p-3 space-y-1">
            {/* 1. Case Info */}
            <button
              onClick={() => setActiveTab('case')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'case'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <FolderKanban className="w-4 h-4" />
                Case Info
              </span>
              <span className="font-mono text-[10px] opacity-75">
                {caseData.caseNumber}
              </span>
            </button>

            {/* 2. Log Sources */}
            <button
              onClick={() => setActiveTab('sources')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'sources'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Layers className="w-4 h-4" />
                Log Sources
              </span>
              <span className="font-mono text-[10px] bg-slate-950/70 px-1.5 py-0.5 rounded border border-slate-800/60 tabular-nums">
                {sources.length}
              </span>
            </button>

            {/* 3. Evidence & Custody */}
            <button
              onClick={() => setActiveTab('evidence')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'evidence'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Shield className="w-4 h-4" />
                Evidence & Custody
              </span>
              <span
                className={`font-mono text-[10px] px-1.5 py-0.5 rounded border tabular-nums ${
                  hasTampering
                    ? 'bg-rose-950 text-rose-300 border-rose-800'
                    : 'bg-slate-950/70 border-slate-800/60 text-slate-400'
                }`}
              >
                {ledger.length} Blocks
              </span>
            </button>

            {/* 4. Investigation Timeline */}
            <button
              onClick={() => setActiveTab('timeline')}
              className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-semibold transition-colors cursor-pointer ${
                activeTab === 'timeline'
                  ? 'bg-sky-600 text-white shadow-sm'
                  : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/60'
              }`}
            >
              <span className="flex items-center gap-2.5">
                <Clock className="w-4 h-4" />
                Investigation Timeline
              </span>
              <span className="font-mono text-[10px] bg-slate-950/70 px-1.5 py-0.5 rounded border border-slate-800/60 tabular-nums">
                {events.length}
              </span>
            </button>
          </nav>
        </div>

        {/* Sidebar Footer with 1-Click Demo Launcher */}
        <div className="p-3 border-t border-slate-800 text-[11px] text-slate-400 space-y-2">
          <div className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-[10px] space-y-1">
            <div className="text-slate-500 font-medium">ACTIVE CASE</div>
            <div className="text-slate-200 font-semibold truncate">
              {caseData.caseNumber}
            </div>
            <div className="text-slate-400 truncate">
              Ref Year: {caseData.referenceDate.slice(0, 4)}
            </div>
          </div>

          <button
            onClick={loadScenario1}
            className="w-full flex items-center justify-center gap-1.5 py-2 px-3 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded text-xs font-semibold shadow-xs transition-all cursor-pointer"
          >
            <Rocket className="w-3.5 h-3.5" />
            <span>🚀 Load SSH Brute-Force Demo</span>
          </button>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col min-w-0 overflow-hidden bg-slate-950">
        {/* Top Header */}
        <header className="h-14 border-b border-slate-800 bg-slate-900/60 px-6 flex items-center justify-between gap-8 shrink-0">
          {/* Breadcrumb / Title */}
          <div className="flex items-center gap-2 text-xs font-medium text-slate-400 truncate">
            <span className="text-slate-200 font-mono">{caseData.caseNumber}</span>
            <span aria-hidden="true">·</span>
            <span className="text-sky-400 truncate font-semibold">{caseData.title}</span>
          </div>

          {/* Quick Header Actions */}
          <div className="flex items-center gap-3 shrink-0">
            <span className="text-[11px] text-slate-400 font-mono hidden sm:inline">
              Examiner: <span className="text-slate-200">{caseData.investigator}</span>
            </span>

            <button
              onClick={() => setShowUtc(!showUtc)}
              className="px-2.5 py-1 text-xs rounded bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono transition-colors cursor-pointer"
            >
              {showUtc ? 'Mode: UTC' : 'Mode: Local'}
            </button>
          </div>
        </header>

        {/* Viewport Content */}
        <div className="flex-1 overflow-y-auto p-4 md:p-6">
          {/* Human-Friendly Forensics Onboarding Banner */}
          <ForensicGuidanceBanner
            onLoadDemoScenario={loadScenario1}
            hasEvents={events.length > 0}
          />

          {/* Responsive Top Stats Overview Widgets */}
          <TopStatsBar
            totalEvents={events.length}
            unparsedCount={unparsedCount}
            hasTampering={hasTampering}
            totalSources={sources.length}
            totalFiles={evidenceFiles.length}
          />

          {isLoading ? (
            <div className="flex flex-col items-center justify-center h-64 text-slate-400 text-xs space-y-2">
              <Shield className="w-8 h-8 text-sky-400 animate-pulse" />
              <span>Normalizing Forensic Timeline & Hashing Evidence...</span>
            </div>
          ) : (
            <>
              {activeTab === 'case' && (
                <CaseView
                  caseData={caseData}
                  onUpdateCase={handleUpdateCase}
                  sources={sources}
                  evidenceFiles={evidenceFiles}
                  events={events}
                  onLoadDemoScenario={loadScenario1}
                />
              )}

              {activeTab === 'sources' && (
                <SourcesView
                  sources={sources}
                  evidenceFiles={evidenceFiles}
                  onAddFiles={handleAddFiles}
                  onUpdateSource={handleUpdateSource}
                  onDeleteSource={handleDeleteSource}
                  onReparseAll={() =>
                    setEvents(reparseAllSources(sources, evidenceFiles, caseData))
                  }
                  onLoadDemoScenario={loadScenario1}
                />
              )}

              {activeTab === 'evidence' && (
                <EvidenceView
                  ledger={ledger}
                  evidenceFiles={evidenceFiles}
                  onVerifyIntegrity={handleVerifyIntegrity}
                  onSimulateTampering={handleSimulateTampering}
                  onRestoreCleanState={handleRestoreCleanState}
                />
              )}

              {activeTab === 'timeline' && (
                <TimelineView
                  events={events}
                  showUtc={showUtc}
                  onToggleUtc={(val) => setShowUtc(val)}
                  onLoadDemoScenario={loadScenario1}
                />
              )}
            </>
          )}
        </div>

        {/* Mandatory Legal & Safety Footer Compliance */}
        <footer className="h-8 border-t border-slate-900 bg-slate-950 px-6 flex items-center justify-between text-[11px] text-slate-500 shrink-0 select-none">
          <span>CyberTrace · Incident Timeline and Evidence Collection (PS-013)</span>
          <span className="font-mono text-amber-500/90 font-medium">
            Not forensically certified. Educational/triage use only.
          </span>
        </footer>
      </main>
    </div>
  );
}

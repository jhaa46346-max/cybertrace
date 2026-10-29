/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import {
  ParsedEvent,
  AITriageRule,
  AIInvestigationReport,
  CaseMetadata,
} from '../types';
import {
  DEFAULT_TRIAGE_RULES,
  trainAndEvaluateRules,
  generateLocalHeuristicInvestigation,
} from '../ai/forensicRules';
import {
  Brain,
  Sparkles,
  ShieldAlert,
  Play,
  Plus,
  Sliders,
  CheckCircle,
  AlertTriangle,
  FileCode,
  Tag,
  Crosshair,
  RotateCcw,
  Bot,
  Layers,
} from 'lucide-react';

interface AITriageViewProps {
  events: ParsedEvent[];
  caseData: CaseMetadata;
  rules: AITriageRule[];
  onSaveRules: (updatedRules: AITriageRule[]) => void;
}

export const AITriageView: React.FC<AITriageViewProps> = ({
  events,
  caseData,
  rules,
  onSaveRules,
}) => {
  const [activeTab, setActiveTab] = useState<'report' | 'trainer'>('report');
  const [report, setReport] = useState<AIInvestigationReport | null>(null);
  const [isInvestigating, setIsInvestigating] = useState(false);
  const [aiBackendStatus, setAiBackendStatus] = useState<{
    available: boolean;
    model: string;
  }>({ available: false, model: 'local-heuristic' });

  // Rule editor state
  const [editingRule, setEditingRule] = useState<Partial<AITriageRule> | null>(null);
  const [trainingPrompt, setTrainingPrompt] = useState('');
  const [isTrainingAi, setIsTrainingAi] = useState(false);

  // Check server AI status
  useEffect(() => {
    fetch('/api/ai/status')
      .then((res) => res.json())
      .then((data) => {
        setAiBackendStatus(data);
      })
      .catch(() => {
        setAiBackendStatus({ available: false, model: 'local-heuristic-engine' });
      });
  }, []);

  // Compute live rule matches across timeline
  const { ruleMatches, totalHits } = trainAndEvaluateRules(events, rules);

  const runInvestigation = async () => {
    setIsInvestigating(true);
    try {
      if (aiBackendStatus.available) {
        const response = await fetch('/api/ai/investigate', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            events,
            rules,
            caseInfo: caseData,
          }),
        });

        if (response.ok) {
          const data = await response.json();
          setReport(data);
          setIsInvestigating(false);
          return;
        }
      }

      // Fallback: Local Forensic Heuristic Synthesis Engine
      const localReport = generateLocalHeuristicInvestigation(events, rules);
      setReport(localReport);
    } catch (err) {
      console.warn('AI investigation error, falling back to local engine:', err);
      const localReport = generateLocalHeuristicInvestigation(events, rules);
      setReport(localReport);
    } finally {
      setIsInvestigating(false);
    }
  };

  const handleTrainAiRule = async () => {
    if (!trainingPrompt.trim()) return;
    setIsTrainingAi(true);

    try {
      if (aiBackendStatus.available) {
        const sampleLogs = events.slice(0, 10).map((e) => e.message);
        const res = await fetch('/api/ai/train-rule', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            description: trainingPrompt,
            targetEvents: sampleLogs,
          }),
        });
        if (res.ok) {
          const generatedRule = await res.json();
          setEditingRule({
            ...generatedRule,
            id: `rule-custom-${Date.now()}`,
            enabled: true,
          });
          setIsTrainingAi(false);
          return;
        }
      }

      // Local Rule Generator fallback
      setEditingRule({
        id: `rule-custom-${Date.now()}`,
        name: `Detection: ${trainingPrompt.slice(0, 30)}`,
        description: `Trained heuristic for: ${trainingPrompt}`,
        patternType: 'regex',
        matchField: 'message',
        patternValue: trainingPrompt.split(' ')[0] || 'failed',
        severity: 'HIGH',
        mitreTechnique: 'T1059 - Command and Scripting Interpreter',
        recommendation: 'Inspect event provenance and restrict user execution privileges.',
        enabled: true,
      });
    } catch {
      // Local fallback
      setEditingRule({
        id: `rule-custom-${Date.now()}`,
        name: `Detection Rule`,
        description: trainingPrompt,
        patternType: 'regex',
        matchField: 'message',
        patternValue: trainingPrompt,
        severity: 'MEDIUM',
        recommendation: 'Review host activity.',
        enabled: true,
      });
    } finally {
      setIsTrainingAi(false);
    }
  };

  const handleSaveRule = (rule: Partial<AITriageRule>) => {
    if (!rule.name || !rule.patternValue) return;

    const completeRule: AITriageRule = {
      id: rule.id || `rule-${Date.now()}`,
      name: rule.name,
      description: rule.description || '',
      patternType: rule.patternType || 'regex',
      matchField: rule.matchField || 'message',
      patternValue: rule.patternValue,
      severity: rule.severity || 'MEDIUM',
      mitreTechnique: rule.mitreTechnique || 'Custom Rule',
      recommendation: rule.recommendation || 'Investigate source activity.',
      enabled: rule.enabled ?? true,
    };

    const existingIndex = rules.findIndex((r) => r.id === completeRule.id);
    let updatedRules: AITriageRule[];
    if (existingIndex >= 0) {
      updatedRules = [...rules];
      updatedRules[existingIndex] = completeRule;
    } else {
      updatedRules = [...rules, completeRule];
    }

    onSaveRules(updatedRules);
    setEditingRule(null);
  };

  const handleToggleRule = (id: string) => {
    const updated = rules.map((r) =>
      r.id === id ? { ...r, enabled: !r.enabled } : r
    );
    onSaveRules(updated);
  };

  const handleDeleteRule = (id: string) => {
    const updated = rules.filter((r) => r.id !== id);
    onSaveRules(updated);
  };

  const handleResetDefaultRules = () => {
    onSaveRules(DEFAULT_TRIAGE_RULES);
  };

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 pb-4 border-b border-slate-800">
        <div>
          <h2 className="text-xl font-bold text-slate-100 flex items-center gap-2">
            <Brain className="w-5 h-5 text-purple-400" />
            AI Forensic Analyst & Detection Rule Trainer
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Correlate timeline events, map attack vectors to MITRE ATT&CK, and train custom forensic detection rules.
          </p>
        </div>

        {/* Tab switch */}
        <div className="flex items-center gap-1 p-1 bg-slate-900 border border-slate-800 rounded-md">
          <button
            onClick={() => setActiveTab('report')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors ${
              activeTab === 'report'
                ? 'bg-purple-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Incident Synthesis Report
          </button>
          <button
            onClick={() => setActiveTab('trainer')}
            className={`px-3 py-1.5 text-xs font-medium rounded transition-colors flex items-center gap-1.5 ${
              activeTab === 'trainer'
                ? 'bg-purple-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            <Sliders className="w-3.5 h-3.5" />
            Rule Trainer ({rules.length})
          </button>
        </div>
      </div>

      {activeTab === 'report' ? (
        /* Report View */
        <div className="space-y-6">
          {/* Action Trigger Card */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="font-semibold text-sm text-slate-100 flex items-center gap-2">
                <Sparkles className="w-4 h-4 text-purple-400" />
                Analyze Incident Timeline ({events.length} Events)
              </div>
              <p className="text-xs text-slate-400">
                Engine: {aiBackendStatus.available ? 'Gemini 3.8 Flash (Server)' : 'Local Forensic Heuristic Engine'}.
                Evaluates intrusion vectors, authentication anomalies, and privilege escalations.
              </p>
            </div>

            <button
              onClick={runInvestigation}
              disabled={isInvestigating || events.length === 0}
              className="flex items-center gap-2 px-4 py-2 bg-gradient-to-r from-purple-600 to-indigo-600 hover:from-purple-500 hover:to-indigo-500 disabled:opacity-40 text-white font-semibold rounded text-xs shadow-md transition-all"
            >
              <Play className="w-3.5 h-3.5 fill-current" />
              {isInvestigating ? 'Synthesizing Timeline...' : 'Run Forensic Analysis'}
            </button>
          </div>

          {/* Results Display */}
          {report ? (
            <div className="space-y-6">
              {/* Executive Summary & Threat Level */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                <div className="flex items-center justify-between pb-3 border-b border-slate-800">
                  <h3 className="font-semibold text-sm text-slate-200">
                    Executive Incident Assessment
                  </h3>
                  <span
                    className={`px-2.5 py-1 rounded text-xs font-mono font-bold ${
                      report.threatLevel === 'CRITICAL'
                        ? 'bg-rose-950 text-rose-300 border border-rose-800'
                        : report.threatLevel === 'HIGH'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : 'bg-sky-950 text-sky-300 border border-sky-800'
                    }`}
                  >
                    THREAT LEVEL: {report.threatLevel}
                  </span>
                </div>

                <p className="text-xs text-slate-300 leading-relaxed font-mono bg-slate-950/60 p-3 rounded border border-slate-800">
                  {report.summary}
                </p>

                {/* Target Entities Strip */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs pt-2">
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">AFFECTED HOSTS</span>
                    <span className="font-mono text-purple-300 font-semibold">
                      {report.affectedEntities.hosts.join(', ') || 'None identified'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">TARGETED USERS</span>
                    <span className="font-mono text-amber-300 font-semibold">
                      {report.affectedEntities.users.join(', ') || 'None identified'}
                    </span>
                  </div>
                  <div className="bg-slate-950 p-2.5 rounded border border-slate-800">
                    <span className="text-slate-500 text-[10px] block">SUSPICIOUS SOURCE IPS</span>
                    <span className="font-mono text-sky-300 font-semibold">
                      {report.affectedEntities.ips.join(', ') || 'None identified'}
                    </span>
                  </div>
                </div>
              </div>

              {/* Attack Timeline Phases */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                <h3 className="font-semibold text-sm text-slate-200 pb-2 border-b border-slate-800">
                  Reconstructed Attack Progression
                </h3>

                <div className="space-y-3">
                  {report.attackTimeline.map((phase, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-1.5"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-rose-300 flex items-center gap-1.5">
                          <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                          Phase #{idx + 1}: {phase.phase}
                        </span>
                        <span className="font-mono text-[11px] text-slate-400">
                          {phase.timestamp.replace('T', ' ').slice(0, 19)} UTC
                        </span>
                      </div>
                      <p className="text-slate-300 font-mono text-[11px]">
                        {phase.description}
                      </p>
                    </div>
                  ))}
                </div>
              </div>

              {/* MITRE ATT&CK Breakdown */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-4">
                <h3 className="font-semibold text-sm text-slate-200 pb-2 border-b border-slate-800">
                  MITRE ATT&CK Matrix Mapping
                </h3>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  {report.mitreMappings.map((m, idx) => (
                    <div
                      key={idx}
                      className="bg-slate-950 border border-slate-800 rounded p-3 text-xs space-y-1 font-mono"
                    >
                      <div className="flex items-center justify-between">
                        <span className="px-1.5 py-0.5 rounded bg-purple-950 border border-purple-800 text-purple-300 text-[10px] font-bold">
                          {m.id}
                        </span>
                        <span className="text-slate-500 text-[10px]">{m.tactic}</span>
                      </div>
                      <div className="text-slate-200 font-sans font-semibold text-xs pt-1">
                        {m.technique}
                      </div>
                      <div className="text-slate-400 text-[11px] pt-1 border-t border-slate-900">
                        Evidence: {m.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Actionable Containment Steps */}
              <div className="bg-slate-900 border border-slate-800 rounded-lg p-5 space-y-3">
                <h3 className="font-semibold text-sm text-slate-200 pb-2 border-b border-slate-800">
                  Actionable Incident Containment Playbook
                </h3>

                <ul className="space-y-2 text-xs text-slate-300">
                  {report.recommendedActions.map((action, idx) => (
                    <li
                      key={idx}
                      className="flex items-start gap-2 bg-slate-950 p-2.5 rounded border border-slate-800"
                    >
                      <span className="w-5 h-5 rounded-full bg-sky-950 border border-sky-800 text-sky-400 flex items-center justify-center shrink-0 font-mono text-[10px]">
                        {idx + 1}
                      </span>
                      <span>{action}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </div>
          ) : (
            <div className="p-12 text-center bg-slate-900/40 rounded-lg border border-slate-800 text-slate-400 text-xs">
              Click &quot;Run Forensic Analysis&quot; above to synthesize the timeline and correlate attack phases.
            </div>
          )}
        </div>
      ) : (
        /* Rule Trainer View */
        <div className="space-y-6">
          {/* Prompt Trainer Bar */}
          <div className="bg-slate-900 border border-slate-800 rounded-lg p-4 space-y-3">
            <div className="text-xs font-semibold text-slate-200 flex items-center justify-between">
              <span className="flex items-center gap-1.5">
                <Bot className="w-4 h-4 text-purple-400" />
                Train Detection AI via Natural Language or Regex
              </span>
              <button
                onClick={handleResetDefaultRules}
                className="text-slate-400 hover:text-slate-200 flex items-center gap-1 text-[11px]"
              >
                <RotateCcw className="w-3 h-3" /> Reset Defaults
              </button>
            </div>

            <div className="flex gap-2">
              <input
                type="text"
                value={trainingPrompt}
                onChange={(e) => setTrainingPrompt(e.target.value)}
                placeholder="e.g. Detect curl script downloads to /tmp or flag failed sudo attempts"
                className="flex-1 bg-slate-950 border border-slate-800 rounded px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={handleTrainAiRule}
                disabled={isTrainingAi || !trainingPrompt.trim()}
                className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 text-white rounded text-xs font-medium flex items-center gap-1.5 transition-colors shrink-0"
              >
                <Sparkles className="w-3.5 h-3.5" />
                {isTrainingAi ? 'Training...' : 'Generate Rule'}
              </button>
            </div>
          </div>

          {/* Active Rules List */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-sm font-semibold text-slate-200">
                Active Detection & Triage Rules ({rules.length})
              </h3>
              <button
                onClick={() =>
                  setEditingRule({
                    id: `rule-${Date.now()}`,
                    name: 'New Custom Rule',
                    description: '',
                    patternType: 'regex',
                    matchField: 'message',
                    patternValue: '',
                    severity: 'MEDIUM',
                    mitreTechnique: '',
                    recommendation: '',
                    enabled: true,
                  })
                }
                className="flex items-center gap-1 px-2.5 py-1 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded text-xs font-medium border border-slate-700 transition-colors"
              >
                <Plus className="w-3.5 h-3.5" /> Add Rule
              </button>
            </div>

            <div className="space-y-3">
              {rules.map((rule) => {
                const matchInfo = ruleMatches[rule.id] || { count: 0, sampleEvents: [] };

                return (
                  <div
                    key={rule.id}
                    className={`bg-slate-900 border rounded-lg p-4 space-y-3 transition-colors ${
                      rule.enabled ? 'border-slate-800' : 'border-slate-800/40 opacity-50'
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 pb-2 border-b border-slate-800 text-xs">
                      <div className="flex items-center gap-2">
                        <input
                          type="checkbox"
                          checked={rule.enabled}
                          onChange={() => handleToggleRule(rule.id)}
                          className="rounded border-slate-700 text-purple-600 focus:ring-0"
                        />
                        <span className="font-semibold text-slate-100">{rule.name}</span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-bold ${
                            rule.severity === 'CRITICAL'
                              ? 'bg-rose-950 text-rose-400'
                              : rule.severity === 'HIGH'
                              ? 'bg-amber-950 text-amber-400'
                              : 'bg-sky-950 text-sky-400'
                          }`}
                        >
                          {rule.severity}
                        </span>
                      </div>

                      <div className="flex items-center gap-3">
                        <span className="font-mono text-purple-400 text-xs font-semibold">
                          {matchInfo.count} Hits on Timeline
                        </span>
                        <button
                          onClick={() => setEditingRule(rule)}
                          className="text-slate-400 hover:text-slate-200"
                        >
                          Edit
                        </button>
                        <button
                          onClick={() => handleDeleteRule(rule.id)}
                          className="text-slate-500 hover:text-rose-400"
                        >
                          Delete
                        </button>
                      </div>
                    </div>

                    <p className="text-xs text-slate-400">{rule.description}</p>

                    <div className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-xs flex flex-wrap items-center gap-2 text-slate-300">
                      <span className="text-slate-500">Match Field:</span>
                      <span className="text-sky-400">{rule.matchField}</span>
                      <span className="text-slate-500">· Pattern ({rule.patternType}):</span>
                      <span className="text-emerald-400 select-all">{rule.patternValue}</span>
                    </div>

                    {rule.mitreTechnique && (
                      <div className="text-[11px] text-purple-300/80 font-mono">
                        MITRE: {rule.mitreTechnique}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Rule Modal Editor */}
          {editingRule && (
            <div className="fixed inset-0 bg-black/70 backdrop-blur-xs flex items-center justify-center p-4 z-50">
              <div className="bg-slate-900 border border-slate-700 rounded-lg max-w-lg w-full p-5 space-y-4 shadow-2xl text-xs">
                <div className="flex items-center justify-between pb-2 border-b border-slate-800 font-semibold text-slate-100 text-sm">
                  <span>Edit Detection Rule</span>
                  <button
                    onClick={() => setEditingRule(null)}
                    className="text-slate-400 hover:text-slate-200"
                  >
                    ✕
                  </button>
                </div>

                <div className="space-y-3">
                  <div>
                    <label className="block text-slate-400 mb-1">Rule Name</label>
                    <input
                      type="text"
                      value={editingRule.name || ''}
                      onChange={(e) =>
                        setEditingRule({ ...editingRule, name: e.target.value })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1">Description</label>
                    <input
                      type="text"
                      value={editingRule.description || ''}
                      onChange={(e) =>
                        setEditingRule({ ...editingRule, description: e.target.value })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="block text-slate-400 mb-1">Target Field</label>
                      <select
                        value={editingRule.matchField || 'message'}
                        onChange={(e) =>
                          setEditingRule({
                            ...editingRule,
                            matchField: e.target.value as any,
                          })
                        }
                        className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                      >
                        <option value="message">message</option>
                        <option value="service">service</option>
                        <option value="user">user</option>
                        <option value="src_ip">src_ip</option>
                        <option value="event_type">event_type</option>
                      </select>
                    </div>

                    <div>
                      <label className="block text-slate-400 mb-1">Severity</label>
                      <select
                        value={editingRule.severity || 'MEDIUM'}
                        onChange={(e) =>
                          setEditingRule({
                            ...editingRule,
                            severity: e.target.value as any,
                          })
                        }
                        className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                      >
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                        <option value="INFO">INFO</option>
                      </select>
                    </div>
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1">
                      Pattern / Regex Value
                    </label>
                    <input
                      type="text"
                      value={editingRule.patternValue || ''}
                      onChange={(e) =>
                        setEditingRule({ ...editingRule, patternValue: e.target.value })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1">MITRE Technique</label>
                    <input
                      type="text"
                      value={editingRule.mitreTechnique || ''}
                      onChange={(e) =>
                        setEditingRule({
                          ...editingRule,
                          mitreTechnique: e.target.value,
                        })
                      }
                      placeholder="e.g. T1110 - Brute Force"
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200 font-mono"
                    />
                  </div>

                  <div>
                    <label className="block text-slate-400 mb-1">
                      Forensic Containment Recommendation
                    </label>
                    <textarea
                      rows={2}
                      value={editingRule.recommendation || ''}
                      onChange={(e) =>
                        setEditingRule({
                          ...editingRule,
                          recommendation: e.target.value,
                        })
                      }
                      className="w-full bg-slate-950 border border-slate-800 rounded p-2 text-slate-200"
                    />
                  </div>
                </div>

                <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                  <button
                    onClick={() => setEditingRule(null)}
                    className="px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 rounded"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={() => handleSaveRule(editingRule)}
                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-500 text-white font-medium rounded"
                  >
                    Save Rule
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

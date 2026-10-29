/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { Search, RotateCcw, Filter, Clock, Calendar, HelpCircle } from 'lucide-react';
import { ForensicTooltip } from '../components/ForensicTooltip';

export interface FilterState {
  searchQuery: string;
  selectedHost: string;
  selectedType: string;
  selectedConfidence: string;
  showUnparsedOnly: boolean;
  timeWindowPreset: 'all' | 'attack_window' | 'custom';
  customStartTime?: string;
  customEndTime?: string;
}

interface TimelineFiltersProps {
  filterState: FilterState;
  onFilterChange: (filters: Partial<FilterState>) => void;
  onResetFilters: () => void;
  hosts: string[];
  showUtc: boolean;
  onToggleUtc: (showUtc: boolean) => void;
  totalEvents: number;
  filteredEventsCount: number;
}

export const TimelineFilters: React.FC<TimelineFiltersProps> = ({
  filterState,
  onFilterChange,
  onResetFilters,
  hosts,
  showUtc,
  onToggleUtc,
  totalEvents,
  filteredEventsCount,
}) => {
  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3 space-y-3">
      {/* Top Bar: Search & UTC Switch */}
      <div className="flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="flex-1 min-w-[240px] relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search logs: user (e.g. root), IP (e.g. 203.0.113.14), sudo command, or line hash..."
            value={filterState.searchQuery}
            onChange={(e) => onFilterChange({ searchQuery: e.target.value })}
            className="w-full bg-slate-950 border border-slate-800 rounded-md pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500 font-mono"
          />
        </div>

        {/* Time Window Presets */}
        <div className="flex items-center gap-1 bg-slate-950 border border-slate-800 rounded-md p-1">
          <Calendar className="w-3.5 h-3.5 text-slate-400 ml-1.5" />
          <select
            value={filterState.timeWindowPreset}
            onChange={(e) =>
              onFilterChange({
                timeWindowPreset: e.target.value as FilterState['timeWindowPreset'],
              })
            }
            className="bg-transparent text-slate-200 text-xs py-0.5 px-2 focus:outline-none"
          >
            <option value="all" className="bg-slate-900">All Time (Full Incident)</option>
            <option value="attack_window" className="bg-slate-900">
              Attack Window Only (08:42 - 08:48)
            </option>
          </select>
        </div>

        {/* UTC vs Original Timestamp Toggle */}
        <div className="flex items-center gap-1.5 p-1 bg-slate-950 border border-slate-800 rounded-md">
          <span className="text-[11px] text-slate-400 px-1.5 flex items-center gap-1">
            <Clock className="w-3.5 h-3.5" /> Time Mode:
          </span>
          <button
            onClick={() => onToggleUtc(false)}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              !showUtc
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Original Log Time
          </button>
          <button
            onClick={() => onToggleUtc(true)}
            className={`px-2.5 py-1 text-xs font-medium rounded transition-colors whitespace-nowrap ${
              showUtc
                ? 'bg-sky-600 text-white'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            Normalized UTC
          </button>
        </div>
      </div>

      {/* Filter Row: Host, Category, Confidence, Reset */}
      <div className="flex flex-wrap items-center gap-2 pt-1 border-t border-slate-800/80 text-xs">
        <div className="flex items-center gap-1 text-slate-400">
          <Filter className="w-3.5 h-3.5" />
          <span>Filters:</span>
        </div>

        {/* Host Filter */}
        <select
          value={filterState.selectedHost}
          onChange={(e) => onFilterChange({ selectedHost: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-sky-500 font-mono"
        >
          <option value="">All Hosts ({hosts.length})</option>
          {hosts.map((h) => (
            <option key={h} value={h}>
              {h}
            </option>
          ))}
        </select>

        {/* Event Type Filter */}
        <select
          value={filterState.selectedType}
          onChange={(e) => onFilterChange({ selectedType: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-sky-500"
        >
          <option value="">All Event Categories</option>
          <option value="auth_fail">Auth Failures (Password/Login)</option>
          <option value="auth_success">Auth Successes (Accepted)</option>
          <option value="privilege_escalation">Privilege Escalation (Sudo/Root)</option>
          <option value="suspicious_activity">Suspicious Activity (Probing/Scans)</option>
          <option value="web_access">Web Access (HTTP 200/300)</option>
          <option value="web_error">Web Errors (HTTP 400/500)</option>
          <option value="unparsed">Unparsed Corrupted Lines</option>
        </select>

        {/* Confidence Filter */}
        <select
          value={filterState.selectedConfidence}
          onChange={(e) => onFilterChange({ selectedConfidence: e.target.value })}
          className="bg-slate-950 border border-slate-800 rounded px-2.5 py-1 text-slate-200 text-xs focus:outline-none focus:border-sky-500"
        >
          <option value="">All Confidence Levels</option>
          <option value="exact">Exact (Embedded Year & Timezone)</option>
          <option value="inferred">Inferred (RFC 3164 Year Derived)</option>
          <option value="skew-corrected">Skew-Adjusted (Server Drift Corrected)</option>
        </select>

        {/* Unparsed Only Toggle */}
        <button
          onClick={() =>
            onFilterChange({ showUnparsedOnly: !filterState.showUnparsedOnly })
          }
          className={`px-2 py-1 rounded text-xs transition-colors border flex items-center gap-1 ${
            filterState.showUnparsedOnly
              ? 'bg-amber-950/60 border-amber-700 text-amber-300 font-semibold'
              : 'border-slate-800 text-slate-400 hover:text-slate-200'
          }`}
        >
          <span>Unparsed Lines Only</span>
        </button>

        {/* Reset */}
        <button
          onClick={onResetFilters}
          className="flex items-center gap-1 text-slate-400 hover:text-slate-200 px-2 py-1 transition-colors ml-auto"
          title="Reset all filters to default"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          <span>Reset</span>
        </button>

        {/* Active count */}
        <span className="text-slate-400 font-mono text-[11px] tabular-nums pl-2 border-l border-slate-800">
          Showing {filteredEventsCount} / {totalEvents} events
        </span>
      </div>
    </div>
  );
};

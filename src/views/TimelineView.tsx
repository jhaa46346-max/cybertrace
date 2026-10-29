/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { ParsedEvent } from '../types';
import { VirtualEventList } from '../timeline/VirtualEventList';
import { TimelineFilters, FilterState } from '../timeline/TimelineFilters';
import { TimelineHistogram } from '../timeline/TimelineHistogram';
import { EventDetailDrawer } from '../timeline/EventDetailDrawer';
import { Clock, ShieldAlert, Sparkles, FilterX, Rocket } from 'lucide-react';

interface TimelineViewProps {
  events: ParsedEvent[];
  showUtc: boolean;
  onToggleUtc: (val: boolean) => void;
  onLoadDemoScenario: () => void;
}

const INITIAL_FILTERS: FilterState = {
  searchQuery: '',
  selectedHost: '',
  selectedType: '',
  selectedConfidence: '',
  showUnparsedOnly: false,
  timeWindowPreset: 'all',
};

export const TimelineView: React.FC<TimelineViewProps> = ({
  events,
  showUtc,
  onToggleUtc,
  onLoadDemoScenario,
}) => {
  const [filters, setFilters] = useState<FilterState>(INITIAL_FILTERS);
  const [selectedEvent, setSelectedEvent] = useState<ParsedEvent | null>(null);

  // Extract distinct hosts for filter dropdown
  const hosts = useMemo(() => {
    return Array.from(new Set(events.map((e) => e.host).filter(Boolean))).sort();
  }, [events]);

  // Apply filters to events
  const filteredEvents = useMemo(() => {
    return events.filter((e) => {
      // Unparsed only filter
      if (filters.showUnparsedOnly && e.event_type !== 'unparsed') {
        return false;
      }

      // Host filter
      if (filters.selectedHost && e.host !== filters.selectedHost) {
        return false;
      }

      // Type filter
      if (filters.selectedType && e.event_type !== filters.selectedType) {
        return false;
      }

      // Confidence filter
      if (
        filters.selectedConfidence &&
        e.confidence !== filters.selectedConfidence
      ) {
        return false;
      }

      // Time Window Preset
      if (filters.timeWindowPreset === 'attack_window') {
        // Attack window is roughly 08:32:00 to 08:48:00 UTC
        const t = new Date(e.normalized_utc).getTime();
        const start = new Date('2026-10-09T08:32:00.000Z').getTime();
        const end = new Date('2026-10-09T08:50:00.000Z').getTime();
        if (t < start || t > end) {
          return false;
        }
      }

      // Full text search
      if (filters.searchQuery.trim()) {
        const q = filters.searchQuery.toLowerCase();
        const matchesMsg = (e.message || '').toLowerCase().includes(q);
        const matchesHost = (e.host || '').toLowerCase().includes(q);
        const matchesService = (e.service || '').toLowerCase().includes(q);
        const matchesUser = (e.user || '').toLowerCase().includes(q);
        const matchesIp = (e.src_ip || '').toLowerCase().includes(q);
        const matchesRaw = (e.raw_ref.rawText || '').toLowerCase().includes(q);
        const matchesHash = (e.raw_ref.lineHash || '').toLowerCase().includes(q);

        if (
          !matchesMsg &&
          !matchesHost &&
          !matchesService &&
          !matchesUser &&
          !matchesIp &&
          !matchesRaw &&
          !matchesHash
        ) {
          return false;
        }
      }

      return true;
    });
  }, [events, filters]);

  return (
    <div className="flex h-full gap-4 max-w-7xl mx-auto">
      {/* Main Timeline Column */}
      <div className="flex-1 flex flex-col space-y-3 min-w-0">
        {/* Histogram Strip */}
        <TimelineHistogram events={filteredEvents} />

        {/* Filter Controls */}
        <TimelineFilters
          filterState={filters}
          onFilterChange={(updates) => setFilters((prev) => ({ ...prev, ...updates }))}
          onResetFilters={() => setFilters(INITIAL_FILTERS)}
          hosts={hosts}
          showUtc={showUtc}
          onToggleUtc={onToggleUtc}
          totalEvents={events.length}
          filteredEventsCount={filteredEvents.length}
        />

        {/* Column Header */}
        <div className="flex items-center px-4 py-2 bg-slate-950 border border-slate-800 rounded-md text-[11px] font-medium text-slate-400 select-none">
          <div className="w-48 shrink-0">TIMESTAMP</div>
          <div className="w-20 shrink-0 text-center">CONFIDENCE</div>
          <div className="w-28 shrink-0 px-2">HOST</div>
          <div className="w-44 shrink-0 px-2">SERVICE / CATEGORY</div>
          <div className="w-36 shrink-0 px-2">USER / IP</div>
          <div className="flex-1 px-2">LOG MESSAGE</div>
          <div className="w-16 shrink-0 text-right">LINE</div>
        </div>

        {/* Virtualized Event List (Supports 10,000+ items) */}
        {events.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center p-12 bg-slate-900 border border-slate-800 rounded-lg text-center space-y-4">
            <Clock className="w-12 h-12 text-slate-600" />
            <div>
              <h3 className="text-base font-semibold text-slate-200">
                Timeline is currently empty
              </h3>
              <p className="text-xs text-slate-400 mt-1 max-w-md">
                No log files have been ingested yet. Upload Linux syslog or Apache access logs in the Sources tab, or load our pre-configured realistic attack scenario.
              </p>
            </div>
            <button
              onClick={onLoadDemoScenario}
              className="flex items-center gap-2 px-5 py-2.5 bg-gradient-to-r from-sky-600 to-indigo-600 hover:from-sky-500 hover:to-indigo-500 text-white rounded-lg text-xs font-semibold shadow-md transition-all cursor-pointer"
            >
              <Rocket className="w-4 h-4" />
              <span>🚀 Load SSH Brute-Force Demo</span>
            </button>
          </div>
        ) : (
          <VirtualEventList
            events={filteredEvents}
            selectedEventId={selectedEvent?.id}
            onSelectEvent={(ev) => setSelectedEvent(ev)}
            showUtc={showUtc}
          />
        )}
      </div>

      {/* Forensic Detail Drawer */}
      {selectedEvent && (
        <EventDetailDrawer
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
          showUtc={showUtc}
        />
      )}
    </div>
  );
};

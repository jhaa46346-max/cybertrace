/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useRef, useState, useEffect, useCallback } from 'react';
import { ParsedEvent } from '../types';
import {
  ShieldAlert,
  AlertTriangle,
  Info,
  CheckCircle2,
  FileQuestion,
  Clock,
  Terminal,
  HelpCircle,
} from 'lucide-react';
import { ForensicTooltip } from '../components/ForensicTooltip';

interface VirtualEventListProps {
  events: ParsedEvent[];
  selectedEventId?: string;
  onSelectEvent: (event: ParsedEvent) => void;
  showUtc: boolean;
  itemHeight?: number;
  overscan?: number;
}

export const VirtualEventList: React.FC<VirtualEventListProps> = ({
  events,
  selectedEventId,
  onSelectEvent,
  showUtc,
  itemHeight = 56,
  overscan = 12,
}) => {
  const containerRef = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [containerHeight, setContainerHeight] = useState(600);

  useEffect(() => {
    const updateHeight = () => {
      if (containerRef.current) {
        setContainerHeight(containerRef.current.clientHeight);
      }
    };
    updateHeight();
    window.addEventListener('resize', updateHeight);
    return () => window.removeEventListener('resize', updateHeight);
  }, []);

  const handleScroll = useCallback(() => {
    if (containerRef.current) {
      setScrollTop(containerRef.current.scrollTop);
    }
  }, []);

  const totalHeight = events.length * itemHeight;
  const startIndex = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan);
  const endIndex = Math.min(
    events.length - 1,
    Math.ceil((scrollTop + containerHeight) / itemHeight) + overscan
  );

  const visibleItems = events.slice(startIndex, endIndex + 1);
  const offsetY = startIndex * itemHeight;

  const renderBadge = (event: ParsedEvent) => {
    switch (event.event_type) {
      case 'privilege_escalation':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold text-rose-400 bg-rose-950/40 px-1.5 py-0.5 rounded border border-rose-900/60 w-fit">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            Privilege Escalation
          </span>
        );
      case 'auth_fail':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold text-amber-400 bg-amber-950/40 px-1.5 py-0.5 rounded border border-amber-900/60 w-fit">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            Auth Failure
          </span>
        );
      case 'auth_success':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold text-emerald-400 bg-emerald-950/40 px-1.5 py-0.5 rounded border border-emerald-900/60 w-fit">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            Auth Success
          </span>
        );
      case 'suspicious_activity':
        return (
          <span className="flex items-center gap-1 text-[11px] font-bold text-purple-400 bg-purple-950/40 px-1.5 py-0.5 rounded border border-purple-900/60 w-fit">
            <ShieldAlert className="w-3.5 h-3.5 shrink-0" />
            Suspicious Probe
          </span>
        );
      case 'web_error':
        return (
          <span className="flex items-center gap-1 text-[11px] font-semibold text-rose-300">
            <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
            HTTP Error
          </span>
        );
      case 'unparsed':
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-slate-400 bg-slate-950 px-1.5 py-0.5 rounded border border-slate-800 w-fit">
            <FileQuestion className="w-3.5 h-3.5 shrink-0" />
            Unparsed Raw
          </span>
        );
      default:
        return (
          <span className="flex items-center gap-1 text-[11px] font-medium text-slate-300">
            <Info className="w-3.5 h-3.5 shrink-0" />
            System Notice
          </span>
        );
    }
  };

  const renderConfidenceBadge = (confidence: ParsedEvent['confidence']) => {
    if (confidence === 'skew-corrected') {
      return (
        <span
          className="text-[10px] text-amber-300 bg-amber-950/60 border border-amber-800/80 px-1.5 py-0.5 rounded font-mono font-medium tracking-tight"
          title="Server clock drift was corrected by subtracting configured offset"
        >
          skew-adj
        </span>
      );
    }
    if (confidence === 'inferred') {
      return (
        <span
          className="text-[10px] text-sky-300 bg-sky-950/60 border border-sky-800/80 px-1.5 py-0.5 rounded font-mono font-medium tracking-tight"
          title="Year was inferred from Case Reference Date (RFC 3164)"
        >
          inferred
        </span>
      );
    }
    return (
      <span
        className="text-[10px] text-slate-400 bg-slate-950 border border-slate-800 px-1.5 py-0.5 rounded font-mono tracking-tight"
        title="Exact timestamp and timezone recorded directly in log"
      >
        exact
      </span>
    );
  };

  return (
    <div
      ref={containerRef}
      onScroll={handleScroll}
      className="relative flex-1 overflow-y-auto border border-slate-800 bg-slate-900/80 rounded-lg select-text"
      style={{ minHeight: '400px' }}
    >
      {events.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-64 text-slate-400 text-sm">
          <Terminal className="w-8 h-8 mb-2 text-slate-600" />
          <span>No events match the current filter criteria.</span>
          <span className="text-xs text-slate-500 mt-1">
            Try loosening search terms or clicking Reset in the filter bar.
          </span>
        </div>
      ) : (
        <div style={{ height: `${totalHeight}px`, position: 'relative' }}>
          <div
            style={{
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              transform: `translateY(${offsetY}px)`,
            }}
          >
            {visibleItems.map((event) => {
              const isSelected = event.id === selectedEventId;
              const displayTime = showUtc
                ? event.normalized_utc.replace('T', ' ').slice(0, 19) + ' UTC'
                : event.original_timestamp;

              return (
                <div
                  key={event.id}
                  onClick={() => onSelectEvent(event)}
                  style={{ height: `${itemHeight}px` }}
                  className={`flex items-center px-4 border-b border-slate-800/80 cursor-pointer text-xs transition-colors ${
                    event.event_type === 'unparsed'
                      ? 'bg-slate-950/50 text-slate-400 hover:bg-slate-900'
                      : isSelected
                      ? 'bg-sky-950/60 border-sky-800 text-slate-100 ring-1 ring-sky-500/30'
                      : 'hover:bg-slate-800/50 text-slate-200'
                  }`}
                >
                  {/* Timestamp column */}
                  <div className="w-48 shrink-0 flex items-center gap-1.5 font-mono tabular-nums text-slate-300">
                    <Clock className="w-3.5 h-3.5 shrink-0 text-slate-500" />
                    <span className="truncate">{displayTime}</span>
                  </div>

                  {/* Confidence tag */}
                  <div className="w-20 shrink-0 text-center">
                    {renderConfidenceBadge(event.confidence)}
                  </div>

                  {/* Host column */}
                  <div className="w-28 shrink-0 px-2 truncate font-mono text-sky-400 font-medium">
                    {event.host}
                  </div>

                  {/* Service & Type */}
                  <div className="w-44 shrink-0 px-2 flex flex-col justify-center truncate">
                    <span className="font-mono text-[11px] text-slate-400 truncate">
                      {event.service}
                    </span>
                    {renderBadge(event)}
                  </div>

                  {/* Principal (User or IP) */}
                  <div className="w-36 shrink-0 px-2 font-mono text-slate-300 truncate">
                    {event.user ? (
                      <span className="text-amber-300 font-semibold">{event.user}</span>
                    ) : event.src_ip ? (
                      <span className="text-purple-300 font-semibold">{event.src_ip}</span>
                    ) : (
                      <span className="text-slate-600">-</span>
                    )}
                  </div>

                  {/* Message (safely escaped as text string) */}
                  <div className="flex-1 truncate px-2 font-mono text-slate-300 select-all">
                    {event.message}
                  </div>

                  {/* Line ref */}
                  <div className="w-16 shrink-0 text-right font-mono text-[11px] text-slate-500">
                    L#{event.raw_ref.lineNumber}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
};

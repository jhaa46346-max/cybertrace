/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useMemo } from 'react';
import { ParsedEvent } from '../types';

interface TimelineHistogramProps {
  events: ParsedEvent[];
  onSelectTimeBucket?: (startUtc: string, endUtc: string) => void;
}

export const TimelineHistogram: React.FC<TimelineHistogramProps> = ({
  events,
}) => {
  const buckets = useMemo(() => {
    if (events.length === 0) return [];

    const validTimes = events
      .map((e) => new Date(e.normalized_utc).getTime())
      .filter((t) => !isNaN(t));

    if (validTimes.length === 0) return [];

    const minTime = Math.min(...validTimes);
    const maxTime = Math.max(...validTimes);
    const diff = maxTime - minTime;
    const bucketCount = 24;
    const bucketDuration = Math.max(1000, Math.ceil(diff / bucketCount));

    const result = Array.from({ length: bucketCount }, (_, i) => {
      const bucketStart = minTime + i * bucketDuration;
      const bucketEnd = bucketStart + bucketDuration;
      return {
        index: i,
        start: bucketStart,
        end: bucketEnd,
        authFail: 0,
        privEsc: 0,
        authSuccess: 0,
        webAccess: 0,
        suspicious: 0,
        other: 0,
        total: 0,
      };
    });

    for (const ev of events) {
      const t = new Date(ev.normalized_utc).getTime();
      if (isNaN(t)) continue;
      const idx = Math.min(
        bucketCount - 1,
        Math.max(0, Math.floor((t - minTime) / bucketDuration))
      );
      const b = result[idx];
      b.total++;
      if (ev.event_type === 'auth_fail') b.authFail++;
      else if (ev.event_type === 'privilege_escalation') b.privEsc++;
      else if (ev.event_type === 'auth_success') b.authSuccess++;
      else if (ev.event_type === 'web_access') b.webAccess++;
      else if (ev.event_type === 'suspicious_activity') b.suspicious++;
      else b.other++;
    }

    return result;
  }, [events]);

  if (buckets.length === 0) return null;

  const maxTotal = Math.max(1, ...buckets.map((b) => b.total));

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-lg p-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-medium text-slate-300">
          Chronological Event Density
        </span>
        <div className="flex items-center gap-3 text-[11px] text-slate-400">
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-rose-500" /> Priv Esc
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-amber-500" /> Auth Fail
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-purple-500" /> Suspicious
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-emerald-500" /> Auth OK
          </span>
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm bg-sky-500" /> Web / Other
          </span>
        </div>
      </div>

      <div className="h-16 flex items-end gap-1 pt-1 border-b border-slate-800">
        {buckets.map((b) => {
          const heightPercent = Math.max(8, (b.total / maxTotal) * 100);
          const timeLabel = new Date(b.start).toISOString().slice(11, 19);

          return (
            <div
              key={b.index}
              className="flex-1 flex flex-col justify-end group relative"
              style={{ height: '100%' }}
            >
              {/* Tooltip on hover */}
              <div className="hidden group-hover:block absolute bottom-full mb-1 left-1/2 -translate-x-1/2 bg-slate-950 border border-slate-800 px-2 py-1 rounded text-[10px] whitespace-nowrap z-30 shadow-lg pointer-events-none">
                <div className="font-mono text-slate-300">{timeLabel} UTC</div>
                <div className="text-slate-400">
                  {b.total} events ({b.authFail} fail, {b.privEsc} priv, {b.suspicious} susp)
                </div>
              </div>

              {/* Stacked bar */}
              <div
                className="w-full rounded-t-sm overflow-hidden flex flex-col justify-end bg-slate-800 hover:brightness-125 transition-all"
                style={{ height: `${b.total > 0 ? heightPercent : 0}%` }}
              >
                {b.privEsc > 0 && (
                  <div
                    style={{ height: `${(b.privEsc / b.total) * 100}%` }}
                    className="w-full bg-rose-500"
                  />
                )}
                {b.authFail > 0 && (
                  <div
                    style={{ height: `${(b.authFail / b.total) * 100}%` }}
                    className="w-full bg-amber-500"
                  />
                )}
                {b.suspicious > 0 && (
                  <div
                    style={{ height: `${(b.suspicious / b.total) * 100}%` }}
                    className="w-full bg-purple-500"
                  />
                )}
                {b.authSuccess > 0 && (
                  <div
                    style={{ height: `${(b.authSuccess / b.total) * 100}%` }}
                    className="w-full bg-emerald-500"
                  />
                )}
                {(b.webAccess > 0 || b.other > 0) && (
                  <div
                    style={{
                      height: `${((b.webAccess + b.other) / b.total) * 100}%`,
                    }}
                    className="w-full bg-sky-600"
                  />
                )}
              </div>
            </div>
          );
        })}
      </div>

      <div className="flex justify-between items-center text-[10px] font-mono text-slate-500 mt-1">
        <span>{new Date(buckets[0].start).toISOString().slice(11, 19)} UTC</span>
        <span>
          {new Date(buckets[buckets.length - 1].end).toISOString().slice(11, 19)} UTC
        </span>
      </div>
    </div>
  );
};

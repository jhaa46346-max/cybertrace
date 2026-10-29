/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { DateTime } from 'luxon';
import { EventConfidence } from '../types';

export interface NormalizationResult {
  utcIso: string;
  notes: string;
  confidence: EventConfidence;
  yearUsed: number;
}

const MONTH_NAMES: Record<string, number> = {
  jan: 1,
  feb: 2,
  mar: 3,
  apr: 4,
  may: 5,
  jun: 6,
  jul: 7,
  aug: 8,
  sep: 9,
  oct: 10,
  nov: 11,
  dec: 12,
};

/**
 * Normalizes RFC 3164 syslog timestamp ("Mmm dd HH:mm:ss" without year or timezone).
 * Resolves year using referenceDate (defaults to incident reference date, e.g. 2026).
 * Handles Dec -> Jan rollover:
 * - If reference date is in January (e.g. Jan 5) and the log entry is December, the log belongs to (referenceYear - 1).
 * - If reference date is in December and log entry is January, it belongs to (referenceYear + 1).
 * Applies source timezone and clock offset.
 */
export function normalizeSyslogTimestamp(
  monthStr: string,
  dayStr: string,
  timeStr: string, // "HH:mm:ss"
  referenceDateIso: string,
  sourceTimezone: string,
  clockOffsetSeconds: number = 0
): NormalizationResult {
  const monthKey = monthStr.toLowerCase().slice(0, 3);
  const month = MONTH_NAMES[monthKey] ?? 1;
  const day = parseInt(dayStr, 10);
  const [hourStr, minStr, secStr] = timeStr.split(':');
  const hour = parseInt(hourStr, 10) || 0;
  const minute = parseInt(minStr, 10) || 0;
  const second = parseInt(secStr, 10) || 0;

  const refDt = DateTime.fromISO(referenceDateIso, { zone: 'utc' }).isValid
    ? DateTime.fromISO(referenceDateIso, { zone: 'utc' })
    : DateTime.now().setZone('utc');

  let year = refDt.year;

  // Handle Dec -> Jan rollover relative to reference date:
  if (refDt.month === 1 && month === 12) {
    year = refDt.year - 1;
  } else if (refDt.month === 12 && month === 1) {
    year = refDt.year + 1;
  }

  // Parse in source timezone
  let dt = DateTime.fromObject(
    {
      year,
      month,
      day,
      hour,
      minute,
      second,
      millisecond: 0,
    },
    { zone: sourceTimezone || 'UTC' }
  );

  if (!dt.isValid) {
    // Fallback if invalid timezone passed
    dt = DateTime.fromObject(
      { year, month, day, hour, minute, second },
      { zone: 'UTC' }
    );
  }

  // Apply clock offset:
  // If the server clock was fast by +X seconds, the true time was (recorded - X).
  // If clockOffsetSeconds represents how much the server clock leads (+) or lags (-):
  // True UTC = dt - clockOffsetSeconds
  const adjustedDt = dt.minus({ seconds: clockOffsetSeconds });
  const utcIso = adjustedDt.toUTC().toISO() || new Date(0).toISOString();

  const notesParts: string[] = [
    `Year inferred: ${year}`,
    `Source TZ: ${sourceTimezone || 'UTC'} (${dt.offsetNameShort || 'UTC'})`,
  ];

  let confidence: EventConfidence = 'inferred';
  if (clockOffsetSeconds !== 0) {
    const sign = clockOffsetSeconds > 0 ? '+' : '';
    notesParts.push(`Clock skew adjusted: ${sign}${clockOffsetSeconds}s`);
    confidence = 'skew-corrected';
  } else {
    notesParts.push('No clock skew offset');
  }

  return {
    utcIso,
    notes: notesParts.join(' | '),
    confidence,
    yearUsed: year,
  };
}

/**
 * Normalizes Apache/Nginx combined log timestamp, e.g. "[09/Oct/2026:08:44:12 +0530]".
 * Has explicit year and explicit timezone offset in the log.
 * Applies optional clock offset.
 */
export function normalizeCombinedLogTimestamp(
  rawCombinedTimestamp: string, // e.g. "09/Oct/2026:08:44:12 +0530" or "[09/Oct/2026:08:44:12 +0530]"
  clockOffsetSeconds: number = 0
): NormalizationResult {
  const cleaned = rawCombinedTimestamp.replace(/^\[|\]$/g, '').trim();

  // Pattern: dd/MMM/yyyy:HH:mm:ss ZZZZ
  // e.g. "09/Oct/2026:08:44:12 +0530"
  let dt = DateTime.fromFormat(cleaned, 'dd/MMM/yyyy:HH:mm:ss ZZZZZ', { setZone: true });
  if (!dt.isValid) {
    // Try without colon before seconds or alternative format
    dt = DateTime.fromFormat(cleaned, 'dd/MMM/yyyy:HH:mm:ss Z', { setZone: true });
  }

  if (!dt.isValid) {
    // Regex manual fallback
    const match = cleaned.match(
      /(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s+([+-]\d{4})/
    );
    if (match) {
      const [, day, mon, yr, hr, mn, sc, tzOffset] = match;
      const monthNum = MONTH_NAMES[mon.toLowerCase()] || 1;
      const tzHours = parseInt(tzOffset.slice(0, 3), 10);
      const tzMinutes = parseInt(tzOffset.slice(3), 10) * (tzHours < 0 ? -1 : 1);
      const totalMinutes = tzHours * 60 + tzMinutes;

      dt = DateTime.fromObject(
        {
          year: parseInt(yr, 10),
          month: monthNum,
          day: parseInt(day, 10),
          hour: parseInt(hr, 10),
          minute: parseInt(mn, 10),
          second: parseInt(sc, 10),
        },
        { zone: `UTC${tzOffset}` }
      );
    }
  }

  if (!dt.isValid) {
    // Fallback to current UTC
    return {
      utcIso: new Date().toISOString(),
      notes: 'Timestamp parsing error: fallback to now',
      confidence: 'inferred',
      yearUsed: new Date().getFullYear(),
    };
  }

  const adjustedDt = dt.minus({ seconds: clockOffsetSeconds });
  const utcIso = adjustedDt.toUTC().toISO() || new Date(0).toISOString();

  const notesParts: string[] = [
    `Explicit timestamp with log TZ (${dt.toFormat('ZZZZ')})`,
  ];

  let confidence: EventConfidence = 'exact';
  if (clockOffsetSeconds !== 0) {
    const sign = clockOffsetSeconds > 0 ? '+' : '';
    notesParts.push(`Clock skew adjusted: ${sign}${clockOffsetSeconds}s`);
    confidence = 'skew-corrected';
  } else {
    notesParts.push('Zero clock skew offset');
  }

  return {
    utcIso,
    notes: notesParts.join(' | '),
    confidence,
    yearUsed: dt.year,
  };
}

/**
 * Formats ISO timestamp to human display string in original or UTC.
 */
export function formatTimestampDisplay(
  isoUtc: string,
  showUtc: boolean,
  targetTimezone: string = 'UTC'
): string {
  if (!isoUtc) return 'N/A';
  const dt = DateTime.fromISO(isoUtc, { zone: 'utc' });
  if (!dt.isValid) return isoUtc;

  if (showUtc) {
    return dt.toFormat('yyyy-MM-dd HH:mm:ss') + ' UTC';
  }

  const localized = dt.setZone(targetTimezone || 'UTC');
  return localized.toFormat('yyyy-MM-dd HH:mm:ss ZZZZ');
}

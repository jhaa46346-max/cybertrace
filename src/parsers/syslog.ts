/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ILogParser, ParseOptions } from './interface';
import { LogSource, ParsedEvent, EventType } from '../types';
import { normalizeSyslogTimestamp } from '../normalize/timezone';

export class SyslogRfc3164Parser implements ILogParser {
  readonly formatId = 'rfc3164_syslog';
  readonly name = 'Linux Syslog / auth.log (RFC 3164)';
  readonly description =
    'Standard UNIX/Linux syslog without year and timezone. Infers year from reference date, handles rollover, and applies source timezone & clock offset.';

  /**
   * Detects if sample lines look like standard RFC 3164 syslog lines
   * e.g. "Oct  9 08:44:12 ..." or "Jan 12 14:02:11 ..."
   */
  detectFormat(sampleLines: string[]): boolean {
    const validLines = sampleLines.filter((l) => l.trim().length > 0);
    if (validLines.length === 0) return false;

    const regex =
      /^(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$/i;

    let matchCount = 0;
    for (const line of validLines.slice(0, 10)) {
      if (regex.test(line)) matchCount++;
    }
    return matchCount / Math.min(validLines.length, 10) >= 0.5;
  }

  parse(
    lines: string[],
    lineHashes: string[],
    source: LogSource,
    options: ParseOptions
  ): ParsedEvent[] {
    const events: ParsedEvent[] = [];
    const rfcRegex =
      /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})(?:\s+([a-zA-Z0-9_.\-]+))?\s+([a-zA-Z0-9_.\-]+?)(?:\[(\d+)\])?:\s*(.*)$/i;

    // Track previous timestamp for fallback when encountering unparsed lines
    let lastValidUtc = options.referenceDateIso || new Date().toISOString();

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const lineHash = lineHashes[i] || '';
      const lineNumber = i + 1;

      // Handle blank lines
      if (!rawLine || rawLine.trim().length === 0) {
        continue;
      }

      const match = rawLine.match(rfcRegex);

      if (!match) {
        // Unparsed line: preserve untouched!
        events.push({
          id: `${source.id}-ev-${lineNumber}`,
          host: source.hostLabel || 'unknown-host',
          source: source.name,
          service: 'unparsed',
          event_type: 'unparsed',
          message: rawLine,
          original_timestamp: '(none)',
          normalized_utc: lastValidUtc,
          normalization_notes:
            'Malformed or non-conforming syslog line. Content preserved untouched; assigned context UTC.',
          confidence: 'inferred',
          raw_ref: {
            fileId: source.fileId || '',
            fileName: source.fileName || 'source.log',
            lineNumber,
            rawText: rawLine,
            lineHash,
          },
        });
        continue;
      }

      const [, monthStr, dayStr, timeStr, logHost, rawService, pid, message] = match;
      const host = logHost || source.hostLabel || 'unknown-host';
      const service = pid ? `${rawService}[${pid}]` : rawService;
      const originalTs = `${monthStr} ${dayStr.padStart(2, ' ')} ${timeStr}`;

      // Normalize timestamp with year inference and clock skew
      const norm = normalizeSyslogTimestamp(
        monthStr,
        dayStr,
        timeStr,
        options.referenceDateIso,
        source.timezone,
        source.clockOffsetSeconds
      );

      lastValidUtc = norm.utcIso;

      // Field extraction from message
      const { user, srcIp, eventType } = this.extractSyslogDetails(
        rawService.toLowerCase(),
        message
      );

      events.push({
        id: `${source.id}-ev-${lineNumber}`,
        host,
        source: source.name,
        service,
        user,
        src_ip: srcIp,
        event_type: eventType,
        message,
        original_timestamp: originalTs,
        normalized_utc: norm.utcIso,
        normalization_notes: norm.notes,
        confidence: norm.confidence,
        raw_ref: {
          fileId: source.fileId || '',
          fileName: source.fileName || 'source.log',
          lineNumber,
          rawText: rawLine,
          lineHash,
        },
      });
    }

    return events;
  }

  private extractSyslogDetails(
    serviceLower: string,
    message: string
  ): { user?: string; srcIp?: string; eventType: EventType } {
    let user: string | undefined;
    let srcIp: string | undefined;
    let eventType: EventType = 'system_notice';

    // Extract IP: look for "from <ip>" or "rhost=<ip>" or "[<ip>]"
    const ipMatch = message.match(
      /(?:from|rhost=|client\s+)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)/i
    );
    if (ipMatch) {
      srcIp = ipMatch[1];
    }

    // SSH authentication failures
    if (
      message.includes('Failed password') ||
      message.includes('authentication failure') ||
      message.includes('Invalid user')
    ) {
      eventType = 'auth_fail';
      const userMatch = message.match(
        /(?:for invalid user|for user|for)\s+([a-zA-Z0-9_.\-]+)/i
      );
      if (userMatch) user = userMatch[1];
    }
    // SSH authentication successes
    else if (
      message.includes('Accepted password') ||
      message.includes('Accepted publickey') ||
      message.includes('session opened for user')
    ) {
      eventType = 'auth_success';
      const userMatch = message.match(
        /(?:for user|for)\s+([a-zA-Z0-9_.\-]+)/i
      );
      if (userMatch) user = userMatch[1];
    }
    // Sudo privilege escalation
    else if (serviceLower === 'sudo') {
      eventType = 'privilege_escalation';
      const sudoUserMatch = message.match(/^\s*([a-zA-Z0-9_.\-]+)\s*:/);
      if (sudoUserMatch) {
        user = sudoUserMatch[1];
      }
      const targetUserMatch = message.match(/USER=([a-zA-Z0-9_.\-]+)/);
      if (targetUserMatch && user) {
        user = `${user} -> ${targetUserMatch[1]}`;
      }
    }
    // Su or PAM elevation
    else if (serviceLower === 'su' || message.includes('session opened for user root')) {
      eventType = 'privilege_escalation';
      const userMatch = message.match(/by\s+([a-zA-Z0-9_.\-]+)/);
      if (userMatch) user = userMatch[1];
    }
    // Suspicious network or intruder activities
    else if (
      message.includes('refused connect') ||
      message.includes('POSSIBLE BREAK-IN ATTEMPT') ||
      message.includes('Did not receive identification')
    ) {
      eventType = 'suspicious_activity';
    }

    return { user, srcIp, eventType };
  }
}

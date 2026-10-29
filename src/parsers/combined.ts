/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ILogParser, ParseOptions } from './interface';
import { LogSource, ParsedEvent, EventType } from '../types';
import { normalizeCombinedLogTimestamp } from '../normalize/timezone';

export class CombinedLogParser implements ILogParser {
  readonly formatId = 'combined_log';
  readonly name = 'Apache / Nginx Combined Log Format';
  readonly description =
    'Standard Web Server access log format with remote client IP, timestamp with embedded timezone offset, HTTP request method/path, status code, referer, and user-agent.';

  detectFormat(sampleLines: string[]): boolean {
    const validLines = sampleLines.filter((l) => l.trim().length > 0);
    if (validLines.length === 0) return false;

    // Pattern: IP - user [date] "METHOD ... " status bytes ...
    const regex =
      /^\S+\s+\S+\s+\S+\s+\[\d{1,2}\/[A-Za-z]{3}\/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4}\]\s+"[A-Z]+\s+[^"]*"\s+\d{3}\s+/;

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

    // Combined Log Format Regex:
    // 1: remote_addr
    // 2: ident (usually -)
    // 3: authuser
    // 4: timestamp inside brackets
    // 5: request line (e.g. GET /index.html HTTP/1.1)
    // 6: status code
    // 7: bytes sent
    // 8: referer (optional)
    // 9: user agent (optional)
    const combinedRegex =
      /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

    let lastValidUtc = options.referenceDateIso || new Date().toISOString();

    for (let i = 0; i < lines.length; i++) {
      const rawLine = lines[i];
      const lineHash = lineHashes[i] || '';
      const lineNumber = i + 1;

      if (!rawLine || rawLine.trim().length === 0) {
        continue;
      }

      const match = rawLine.match(combinedRegex);

      if (!match) {
        // Unparsed line: preserve untouched!
        events.push({
          id: `${source.id}-ev-${lineNumber}`,
          host: source.hostLabel || 'web-server',
          source: source.name,
          service: 'unparsed',
          event_type: 'unparsed',
          message: rawLine,
          original_timestamp: '(none)',
          normalized_utc: lastValidUtc,
          normalization_notes:
            'Malformed or non-conforming Combined Log line. Content preserved untouched; assigned context UTC.',
          confidence: 'inferred',
          raw_ref: {
            fileId: source.fileId || '',
            fileName: source.fileName || 'access.log',
            lineNumber,
            rawText: rawLine,
            lineHash,
          },
        });
        continue;
      }

      const [
        ,
        remoteAddr,
        ,
        authUser,
        rawTimestamp,
        requestLine,
        statusCodeStr,
        bytesSent,
        referer,
        userAgent,
      ] = match;

      const statusCode = parseInt(statusCodeStr, 10);
      const user = authUser !== '-' ? authUser : undefined;
      const srcIp = remoteAddr;

      // Normalize timestamp with offset
      const norm = normalizeCombinedLogTimestamp(
        rawTimestamp,
        source.clockOffsetSeconds
      );
      lastValidUtc = norm.utcIso;

      // Classify event type and format message
      const eventType = this.classifyWebEvent(statusCode, requestLine);

      // Clean message string
      const message = `[${statusCodeStr}] ${requestLine} (${bytesSent} bytes)${
        userAgent && userAgent !== '-' ? ` UA: ${userAgent}` : ''
      }`;

      events.push({
        id: `${source.id}-ev-${lineNumber}`,
        host: source.hostLabel || 'web-server',
        source: source.name,
        service: 'web-access',
        user,
        src_ip: srcIp,
        event_type: eventType,
        message,
        original_timestamp: rawTimestamp,
        normalized_utc: norm.utcIso,
        normalization_notes: norm.notes,
        confidence: norm.confidence,
        raw_ref: {
          fileId: source.fileId || '',
          fileName: source.fileName || 'access.log',
          lineNumber,
          rawText: rawLine,
          lineHash,
        },
      });
    }

    return events;
  }

  private classifyWebEvent(statusCode: number, requestLine: string): EventType {
    const reqLower = requestLine.toLowerCase();

    // Check for suspicious probe/exploit patterns
    const isSuspicious =
      reqLower.includes('/.env') ||
      reqLower.includes('wp-login') ||
      reqLower.includes('phpmyadmin') ||
      reqLower.includes('..%2f') ||
      reqLower.includes('../') ||
      reqLower.includes('cmd=') ||
      reqLower.includes('etc/passwd') ||
      reqLower.includes('eval(') ||
      reqLower.includes('select%20') ||
      reqLower.includes('union%20');

    if (isSuspicious) {
      return 'suspicious_activity';
    }

    if (statusCode === 401 || statusCode === 403) {
      return 'auth_fail';
    }

    if (statusCode >= 500) {
      return 'web_error';
    }

    return 'web_access';
  }
}

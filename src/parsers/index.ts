/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { ILogParser, ParseOptions } from './interface';
import { SyslogRfc3164Parser } from './syslog';
import { CombinedLogParser } from './combined';
import { LogFormat, LogSource, ParsedEvent } from '../types';

export * from './interface';
export * from './syslog';
export * from './combined';

const parsers: Record<LogFormat, ILogParser> = {
  rfc3164_syslog: new SyslogRfc3164Parser(),
  combined_log: new CombinedLogParser(),
  generic: new SyslogRfc3164Parser(), // fallback
};

export function getParser(format: LogFormat): ILogParser {
  return parsers[format] || parsers.generic;
}

export function autoDetectFormat(lines: string[]): LogFormat {
  if (parsers.combined_log.detectFormat(lines)) {
    return 'combined_log';
  }
  if (parsers.rfc3164_syslog.detectFormat(lines)) {
    return 'rfc3164_syslog';
  }
  return 'rfc3164_syslog';
}

/**
 * Splits raw content into lines preserving all content.
 */
export function splitLines(content: string): string[] {
  return content.split(/\r?\n/);
}

/**
 * Master parser runner: parses a raw text file given its precomputed line hashes and source configuration.
 */
export function parseLogFile(
  content: string,
  lineHashes: string[],
  source: LogSource,
  options: ParseOptions
): ParsedEvent[] {
  const lines = splitLines(content);
  const parser = getParser(source.format);
  return parser.parse(lines, lineHashes, source, options);
}

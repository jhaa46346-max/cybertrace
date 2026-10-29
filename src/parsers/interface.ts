/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { LogSource, ParsedEvent } from '../types';

export interface ParseOptions {
  referenceDateIso: string;
  defaultHostLabel?: string;
}

export interface ILogParser {
  readonly formatId: string;
  readonly name: string;
  readonly description: string;

  /**
   * Can this parser handle the given sample log lines?
   */
  detectFormat(sampleLines: string[]): boolean;

  /**
   * Parses raw lines into normalized ParsedEvents.
   * Every line must be represented — unparsed/corrupt lines must never be dropped.
   */
  parse(
    lines: string[],
    lineHashes: string[],
    source: LogSource,
    options: ParseOptions
  ): ParsedEvent[];
}

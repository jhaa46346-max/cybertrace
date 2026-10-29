/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { AITriageRule, AIInvestigationReport, ParsedEvent } from '../types';

export const DEFAULT_TRIAGE_RULES: AITriageRule[] = [
  {
    id: 'rule-ssh-brute-force',
    name: 'SSH Password Brute Force Pattern',
    description: 'Detects repeated failed authentication attempts against SSH daemon.',
    patternType: 'regex',
    matchField: 'message',
    patternValue: 'Failed password|Invalid user',
    severity: 'HIGH',
    mitreTechnique: 'T1110 - Brute Force',
    recommendation: 'Block source IP at edge firewall, review SSH key-only enforcement, disable password auth.',
    enabled: true,
  },
  {
    id: 'rule-root-shell-elevation',
    name: 'Interactive Root Shell via Sudo',
    description: 'Detects non-root user spawning interactive shell via sudo (COMMAND=/bin/bash, /bin/sh, or -s).',
    patternType: 'regex',
    matchField: 'message',
    patternValue: 'COMMAND=(?:/bin/bash|/bin/sh|/bin/zsh|su|sudo -s)',
    severity: 'CRITICAL',
    mitreTechnique: 'T1548.003 - Sudo Caching / Sudoers Privilege Escalation',
    recommendation: 'Immediately revoke user session, rotate root credentials, inspect bash history and audit logs.',
    enabled: true,
  },
  {
    id: 'rule-credential-dumping',
    name: 'Sensitive Credential File Access',
    description: 'Detects command execution targeting /etc/shadow or credential repositories.',
    patternType: 'regex',
    matchField: 'message',
    patternValue: '/etc/shadow|/etc/security|id_rsa|\\.ssh/authorized_keys',
    severity: 'CRITICAL',
    mitreTechnique: 'T1003 - OS Credential Dumping',
    recommendation: 'Assume all system passwords compromised. Force organization-wide password reset.',
    enabled: true,
  },
  {
    id: 'rule-web-scanner-probe',
    name: 'Web Application Reconnaissance',
    description: 'Detects probing for environment files, CMS admin logins, and database managers.',
    patternType: 'regex',
    matchField: 'message',
    patternValue: '/\\.env|wp-login\\.php|phpmyadmin|config\\.json',
    severity: 'MEDIUM',
    mitreTechnique: 'T1595.002 - Vulnerability Scanning',
    recommendation: 'Verify endpoints are blocked or 404, check WAF rules, add IP to temporary blocklist.',
    enabled: true,
  },
  {
    id: 'rule-tool-transfer',
    name: 'Remote Payload Ingress via Curl/Wget',
    description: 'Detects shell command downloading remote scripts or executables to /tmp or /var/tmp.',
    patternType: 'regex',
    matchField: 'message',
    patternValue: '(?:curl|wget)\\s+.*http|chmod\\s+\\+x\\s+/tmp',
    severity: 'HIGH',
    mitreTechnique: 'T1105 - Ingress Tool Transfer',
    recommendation: 'Isolate host from network, extract /tmp directory forensic image, inspect drop script.',
    enabled: true,
  },
  {
    id: 'rule-unparsed-tamper-check',
    name: 'Unparsed Corrupted Log Indicator',
    description: 'Detects lines that failed protocol parsing. Could indicate binary injection or log truncation.',
    patternType: 'heuristic',
    matchField: 'event_type',
    patternValue: 'unparsed',
    severity: 'LOW',
    mitreTechnique: 'T1070 - Indicator Removal on Host',
    recommendation: 'Inspect raw line hex bytes in side panel to rule out evasion tampering or storage corruption.',
    enabled: true,
  },
];

/**
 * Evaluates an event against a specific triage rule.
 */
export function evaluateEventAgainstRule(
  event: ParsedEvent,
  rule: AITriageRule
): boolean {
  if (!rule.enabled) return false;

  let targetValue = '';
  switch (rule.matchField) {
    case 'message':
      targetValue = event.message || '';
      break;
    case 'service':
      targetValue = event.service || '';
      break;
    case 'user':
      targetValue = event.user || '';
      break;
    case 'src_ip':
      targetValue = event.src_ip || '';
      break;
    case 'event_type':
      targetValue = event.event_type || '';
      break;
  }

  if (!targetValue) return false;

  try {
    const regex = new RegExp(rule.patternValue, 'i');
    return regex.test(targetValue);
  } catch {
    return targetValue.toLowerCase().includes(rule.patternValue.toLowerCase());
  }
}

/**
 * Evaluates all events against all enabled rules and returns hit statistics per rule.
 */
export function trainAndEvaluateRules(
  events: ParsedEvent[],
  rules: AITriageRule[]
): {
  ruleMatches: Record<string, { count: number; sampleEvents: ParsedEvent[] }>;
  totalHits: number;
} {
  const ruleMatches: Record<
    string,
    { count: number; sampleEvents: ParsedEvent[] }
  > = {};

  for (const rule of rules) {
    ruleMatches[rule.id] = { count: 0, sampleEvents: [] };
  }

  let totalHits = 0;

  for (const event of events) {
    for (const rule of rules) {
      if (evaluateEventAgainstRule(event, rule)) {
        ruleMatches[rule.id].count++;
        if (ruleMatches[rule.id].sampleEvents.length < 5) {
          ruleMatches[rule.id].sampleEvents.push(event);
        }
        totalHits++;
      }
    }
  }

  return { ruleMatches, totalHits };
}

/**
 * Generates an automated incident triage and timeline synthesis report
 * using the rule-matched heuristics and event correlation.
 */
export function generateLocalHeuristicInvestigation(
  events: ParsedEvent[],
  rules: AITriageRule[]
): AIInvestigationReport {
  const hosts = Array.from(new Set(events.map((e) => e.host).filter(Boolean)));
  const users = Array.from(
    new Set(events.map((e) => e.user).filter((u): u is string => Boolean(u)))
  );
  const ips = Array.from(
    new Set(events.map((e) => e.src_ip).filter((ip): ip is string => Boolean(ip)))
  );

  const matchedRules = rules.filter((r) => r.enabled);
  const hitsBySeverity: Record<string, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };

  const attackPhases: AIInvestigationReport['attackTimeline'] = [];
  const mitreSet = new Map<string, { technique: string; tactic: string; evidence: string }>();

  // Scan through events in chronological order
  for (const ev of events) {
    for (const rule of matchedRules) {
      if (evaluateEventAgainstRule(ev, rule)) {
        hitsBySeverity[rule.severity] = (hitsBySeverity[rule.severity] || 0) + 1;

        if (rule.mitreTechnique && !mitreSet.has(rule.mitreTechnique)) {
          mitreSet.set(rule.mitreTechnique, {
            technique: rule.mitreTechnique,
            tactic: rule.severity === 'CRITICAL' ? 'Privilege Escalation' : 'Initial Access',
            evidence: `${ev.normalized_utc}: ${ev.service} - ${ev.message.slice(0, 80)}`,
          });
        }

        if (rule.severity === 'CRITICAL' || rule.severity === 'HIGH') {
          attackPhases.push({
            timestamp: ev.normalized_utc,
            phase: rule.name,
            description: `${ev.host} | ${ev.service}: ${ev.message}`,
            evidenceIds: [ev.id],
          });
        }
      }
    }
  }

  let overallThreat: AIInvestigationReport['threatLevel'] = 'LOW';
  if (hitsBySeverity.CRITICAL > 0) overallThreat = 'CRITICAL';
  else if (hitsBySeverity.HIGH > 0) overallThreat = 'HIGH';
  else if (hitsBySeverity.MEDIUM > 0) overallThreat = 'MEDIUM';

  const mitreMappings = Array.from(mitreSet.entries()).map(([key, val]) => ({
    id: key.split(' - ')[0],
    technique: val.technique,
    tactic: val.tactic,
    evidence: val.evidence,
  }));

  const recommendedActions = [
    'Immediately isolate affected host from production VLAN.',
    'Invalidate all active SSH and web session tokens for compromised user accounts.',
    'Preserve forensic image of storage and export hash-chained custody ledger.',
    'Update edge firewall to block malicious scanning IP addresses.',
    'Audit sudoers configurations for NOPASSWD or unrestricted shell access.',
  ];

  const summary = `Forensic analysis evaluated ${events.length} unified timeline events across ${
    hosts.length
  } host(s). Detected ${hitsBySeverity.CRITICAL} critical and ${
    hitsBySeverity.HIGH
  } high-severity IOCs. ${
    ips.length > 0 ? `Primary suspect IP(s): ${ips.join(', ')}.` : ''
  } ${
    users.length > 0 ? `Targeted/compromised account(s): ${users.join(', ')}.` : ''
  }`;

  return {
    summary,
    threatLevel: overallThreat,
    attackTimeline: attackPhases.slice(0, 10),
    affectedEntities: {
      hosts,
      users,
      ips,
    },
    mitreMappings,
    recommendedActions,
    generatedBy: 'local-heuristic-engine',
  };
}

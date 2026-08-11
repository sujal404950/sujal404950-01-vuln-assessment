# Vulnerability Assessment Report — Lab Environment

**Prepared by:** [Your Name]
**Date:** [Date]
**Classification:** Internal / Lab Use Only

---

## 1. Executive Summary

A vulnerability assessment was performed against a single host,
**Metasploitable2 (192.168.56.101)**, within an isolated lab network.
The purpose of this exercise was to practice the reconnaissance,
enumeration, and reporting phases of a vulnerability assessment
methodology in a safe, legal, and controlled environment.

The assessment identified **6 findings**, including **2 Critical**,
**2 High**, and **2 Medium** severity issues. The most significant
finding was a backdoored FTP service (vsftpd 2.3.4) that allows
unauthenticated remote root access.

## 2. Scope & Authorization

| Item | Detail |
|------|--------|
| Target | 192.168.56.101 (Metasploitable2) |
| Network | VirtualBox host-only adapter (isolated) |
| Authorization | Self-owned lab VM; no external systems tested |
| Testing window | [Date/time] |
| Excluded | N/A — single-host lab exercise |

## 3. Methodology

This assessment followed a simplified version of the standard VA
process:

1. **Reconnaissance** — identify live hosts on the lab network
2. **Port scanning** — identify open TCP/UDP ports
3. **Service enumeration** — fingerprint service names and versions
4. **Vulnerability correlation** — match service versions against
   known CVEs
5. **Risk rating** — classify findings by severity and exploitability
6. **Reporting** — document findings and remediation guidance

Tools used: `nmap`, custom Python correlation script
(`vuln_scan.py`), manual verification against public CVE
descriptions.

## 4. Findings Summary

| # | Finding | Service | Severity | CVE |
|---|---------|---------|----------|-----|
| 1 | vsftpd backdoor | FTP (21) | Critical | CVE-2011-2523 |
| 2 | Samba usermap script RCE | Samba (139/445) | Critical | CVE-2007-2447 |
| 3 | ProFTPD stack overflow | FTP (21) | High | CVE-2010-4221 |
| 4 | MySQL auth bypass | MySQL (3306) | High | CVE-2012-2122 |
| 5 | Outdated Apache | HTTP (80) | Medium | Multiple |
| 6 | Outdated OpenSSH | SSH (22) | Medium | CVE-2008-5161 |

## 5. Detailed Findings

### 5.1 vsftpd 2.3.4 Backdoor — Critical
**CVE:** CVE-2011-2523
**Port:** 21/tcp

The FTP service is running vsftpd 2.3.4, a version of the software
that was compromised and redistributed with a hidden backdoor. Sending
a username containing `:)` opens a listener on port 6200 that provides
an unauthenticated root shell.

**Impact:** Full remote compromise of the host with no credentials
required.

**Remediation:** Upgrade vsftpd to a current, non-compromised release.
Verify package checksums when installing FTP services in the future.

---

### 5.2 Samba Username Map Script Command Injection — Critical
**CVE:** CVE-2007-2447
**Port:** 139/445 tcp

The Samba `usermap script` configuration option allows shell
metacharacters in the username field to be executed by the underlying
shell, resulting in remote command execution as root.

**Impact:** Full remote compromise.

**Remediation:** Upgrade Samba; disable `usermap script` unless
strictly required and sanitize any user-supplied input.

---

### 5.3 ProFTPD 1.3.1 Buffer Overflow — High
**CVE:** CVE-2010-4221

A stack buffer overflow in ProFTPD's handling of Telnet IAC sequences
allows a remote, unauthenticated attacker to execute arbitrary code.

**Remediation:** Upgrade to a patched ProFTPD release.

---

### 5.4 MySQL Authentication Bypass — High
**CVE:** CVE-2012-2122

Due to a flaw in how MySQL compares password hashes, an attacker can
bypass authentication with a high probability of success simply by
repeating login attempts.

**Remediation:** Upgrade MySQL/MariaDB to a patched version.

---

### 5.5 Outdated Apache HTTP Server — Medium

The web server is running an end-of-life Apache release with multiple
unpatched CVEs accumulated over its lifetime.

**Remediation:** Upgrade to a current, supported Apache release and
enable automatic security updates where possible.

---

### 5.6 Outdated OpenSSH — Medium
**CVE:** CVE-2008-5161

An older OpenSSH version is in use, potentially vulnerable to a CBC
mode plaintext-recovery attack under specific configurations.

**Remediation:** Upgrade OpenSSH and disable CBC ciphers in favor of
GCM/CTR modes.

## 6. Risk Rating Methodology

Severity was assigned using a simplified qualitative model:

- **Critical** — Unauthenticated remote code execution / full host compromise
- **High** — Authentication bypass or RCE requiring some precondition
- **Medium** — Outdated software with known but less severe issues, or
  requiring local/adjacent access
- **Low** — Information disclosure, minor misconfigurations

## 7. Overall Recommendations

1. Patch/upgrade all identified services to current stable versions.
2. Disable unused services (this host runs several legacy services
   with no business justification in a production environment).
3. Implement a patch management process to avoid running end-of-life
   software.
4. In a real environment: re-scan after remediation to confirm fixes.

## 8. Disclaimer

This assessment was conducted entirely against a self-hosted,
intentionally vulnerable training VM (Metasploitable2) within an
isolated virtual network with no connection to production systems or
third-party infrastructure. No real-world systems were tested.

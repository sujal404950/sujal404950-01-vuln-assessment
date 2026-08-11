# Vulnerability Assessment Report
**Target:** 192.168.56.101  
**Scan time:** 2026-08-07T07:19:27  

## Host: 192.168.56.101 (up)

| Port | Service | Banner | Findings |
|------|---------|--------|----------|
| 21/tcp | ftp | vsftpd 2.3.4 | **Critical** CVE-2011-2523 |
| 22/tcp | ssh | OpenSSH 4.7p1 | **Medium** CVE-2008-5161 |
| 80/tcp | http | Apache httpd 2.2.8 | - |
| 139/tcp | netbios-ssn | Samba smbd 3.0.20 | - |
| 3306/tcp | mysql | MySQL 5.0.51a | **High** CVE-2012-2122 |

### Detailed Findings

#### CVE-2011-2523 — Critical severity
- **Service:** vsftpd 2.3.4 (port 21)
- **Description:** vsftpd 2.3.4 contains a backdoor triggered by a ':)' smiley in the username, giving a remote root shell.
- **Recommendation:** Upgrade to the latest stable release, or disable the service if unused.

#### CVE-2008-5161 — Medium severity
- **Service:** OpenSSH 4.7p1 (port 22)
- **Description:** Older OpenSSH versions are vulnerable to a CBC plaintext recovery attack under certain configurations.
- **Recommendation:** Upgrade to the latest stable release, or disable the service if unused.

#### CVE-2012-2122 — High severity
- **Service:** MySQL 5.0.51a (port 3306)
- **Description:** Authentication bypass allowing repeated login attempts to eventually succeed due to a memcmp() flaw.
- **Recommendation:** Upgrade to the latest stable release, or disable the service if unused.


---
**Summary:** 3 known-vulnerability signature match(es) found across 1 host(s).
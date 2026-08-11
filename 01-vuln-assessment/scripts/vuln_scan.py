                      
"""
vuln_scan.py — Lab Vulnerability Assessment Toolkit
-----------------------------------------------------
Automates the reconnaissance + service enumeration phase of a basic
vulnerability assessment against a machine in an isolated lab network
(e.g. Metasploitable2, DVWA, or a deliberately vulnerable VM).

WARNING: Only run this against machines you own or are explicitly
authorized to test. Running this against systems you don't control
is illegal in most jurisdictions.

What it does:
  1. Host discovery + open port scan (via nmap)
  2. Service/version detection on open ports
  3. Cross-references detected service versions against a small local
     "known vulnerable version" lookup table (offline, no API needed)
  4. Generates a structured findings report (Markdown + JSON)

Usage:
    python3 vuln_scan.py --target 192.168.56.101 --output report

Requirements:
    - nmap installed and on PATH
    - python-nmap (pip install python-nmap)
"""

import argparse
import json
import subprocess
import sys
from datetime import datetime

try:
    import nmap
except ImportError:
    print("[!] Missing dependency. Install with: pip install python-nmap")
    sys.exit(1)


                                                                      
                                                                     
                                                                  
                                                                    
               
KNOWN_VULNERABLE_SIGNATURES = [
    {
        "match": "vsftpd 2.3.4",
        "cve": "CVE-2011-2523",
        "severity": "Critical",
        "description": "vsftpd 2.3.4 contains a backdoor triggered by a "
                        "':)' smiley in the username, giving a remote root shell.",
    },
    {
        "match": "OpenSSH 4.7",
        "cve": "CVE-2008-5161",
        "severity": "Medium",
        "description": "Older OpenSSH versions are vulnerable to a CBC "
                        "plaintext recovery attack under certain configurations.",
    },
    {
        "match": "Apache 2.2.8",
        "cve": "Multiple",
        "severity": "Medium",
        "description": "EOL Apache version with multiple unpatched CVEs; "
                        "no longer receives security updates.",
    },
    {
        "match": "ProFTPD 1.3.1",
        "cve": "CVE-2010-4221",
        "severity": "High",
        "description": "ProFTPD 1.3.1 telnet IAC stack buffer overflow "
                        "allows remote code execution.",
    },
    {
        "match": "MySQL 5.0",
        "cve": "CVE-2012-2122",
        "severity": "High",
        "description": "Authentication bypass allowing repeated login "
                        "attempts to eventually succeed due to a memcmp() flaw.",
    },
    {
        "match": "Samba 3.0.20",
        "cve": "CVE-2007-2447",
        "severity": "Critical",
        "description": "Username map script command injection allows "
                        "remote command execution as root.",
    },
    {
        "match": "UnrealIRCd 3.2.8.1",
        "cve": "CVE-2010-2075",
        "severity": "Critical",
        "description": "Backdoored source distribution allows remote "
                        "command execution.",
    },
]


def run_scan(target: str):
    """Run an nmap service/version scan against the target."""
    scanner = nmap.PortScanner()
    print(f"[*] Scanning {target} (this may take 30-90s)...")
                                                                          
                                           
    scanner.scan(target, arguments="-sV -T4 -Pn")
    return scanner


def correlate_vulnerabilities(service_banner: str):
    """Check a service banner string against known vulnerable signatures."""
    findings = []
    for sig in KNOWN_VULNERABLE_SIGNATURES:
        if sig["match"].lower() in service_banner.lower():
            findings.append(sig)
    return findings


def build_report(scanner, target: str):
    report = {
        "target": target,
        "scan_time": datetime.now().isoformat(timespec="seconds"),
        "hosts": [],
    }

    for host in scanner.all_hosts():
        host_data = {
            "ip": host,
            "state": scanner[host].state(),
            "open_ports": [],
        }

        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in sorted(ports):
                port_info = scanner[host][proto][port]
                banner = f"{port_info.get('product', '')} {port_info.get('version', '')}".strip()
                entry = {
                    "port": port,
                    "protocol": proto,
                    "state": port_info.get("state"),
                    "service": port_info.get("name"),
                    "banner": banner if banner else "unknown",
                    "vulnerabilities": correlate_vulnerabilities(banner) if banner else [],
                }
                host_data["open_ports"].append(entry)

        report["hosts"].append(host_data)

    return report


def render_markdown(report: dict) -> str:
    lines = []
    lines.append(f"# Vulnerability Assessment Report")
    lines.append(f"**Target:** {report['target']}  ")
    lines.append(f"**Scan time:** {report['scan_time']}  \n")

    total_findings = 0

    for host in report["hosts"]:
        lines.append(f"## Host: {host['ip']} ({host['state']})\n")
        lines.append("| Port | Service | Banner | Findings |")
        lines.append("|------|---------|--------|----------|")

        for p in host["open_ports"]:
            findings_str = "-"
            if p["vulnerabilities"]:
                total_findings += len(p["vulnerabilities"])
                findings_str = "; ".join(
                    f"**{v['severity']}** {v['cve']}" for v in p["vulnerabilities"]
                )
            lines.append(
                f"| {p['port']}/{p['protocol']} | {p['service']} | {p['banner']} | {findings_str} |"
            )

                                   
        detailed = [p for p in host["open_ports"] if p["vulnerabilities"]]
        if detailed:
            lines.append("\n### Detailed Findings\n")
            for p in detailed:
                for v in p["vulnerabilities"]:
                    lines.append(f"#### {v['cve']} — {v['severity']} severity")
                    lines.append(f"- **Service:** {p['banner']} (port {p['port']})")
                    lines.append(f"- **Description:** {v['description']}")
                    lines.append(f"- **Recommendation:** Upgrade to the latest "
                                  f"stable release, or disable the service if unused.\n")

    lines.append(f"\n---\n**Summary:** {total_findings} known-vulnerability "
                  f"signature match(es) found across {len(report['hosts'])} host(s).")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Lab Vulnerability Assessment Scanner")
    parser.add_argument("--target", required=True, help="IP or hostname of the lab target")
    parser.add_argument("--output", default="report", help="Output file prefix (default: report)")
    args = parser.parse_args()

    scanner = run_scan(args.target)
    report = build_report(scanner, args.target)

    with open(f"{args.output}.json", "w") as f:
        json.dump(report, f, indent=2)

    md = render_markdown(report)
    with open(f"{args.output}.md", "w") as f:
        f.write(md)

    print(f"[+] Report written to {args.output}.md and {args.output}.json")


if __name__ == "__main__":
    main()

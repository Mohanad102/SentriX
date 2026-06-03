"""
BM25-based in-memory knowledge base for RAG.
Indexes: curated security knowledge + DB incidents + playbooks.
No external dependencies — pure Python + stdlib only.
"""
from __future__ import annotations
import math
import re
from collections import Counter
from typing import Dict, List, Optional

# ── Tokenizer ─────────────────────────────────────────────────────────────────

_STOPWORDS = {
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "of", "in", "on", "at",
    "to", "for", "with", "by", "from", "and", "or", "but", "not", "this",
    "that", "it", "its", "as", "if", "then", "so", "also", "when", "how",
    "what", "which", "all", "any", "each", "more", "most", "such",
}


def _tokenize(text: str) -> List[str]:
    tokens = re.findall(r"[a-z0-9_\-\.\/]+", text.lower())
    return [t for t in tokens if t not in _STOPWORDS and len(t) > 1]


# ── BM25 engine ───────────────────────────────────────────────────────────────

class _BM25:
    def __init__(self, k1: float = 1.5, b: float = 0.75):
        self.k1 = k1
        self.b = b
        self._docs: List[str] = []
        self._tokenized: List[List[str]] = []
        self._idf: Dict[str, float] = {}
        self._avg_dl: float = 1.0

    def fit(self, documents: List[str]) -> None:
        self._docs = documents
        N = len(documents)
        if N == 0:
            return
        df: Dict[str, int] = {}
        total_len = 0
        self._tokenized = []
        for doc in documents:
            tokens = _tokenize(doc)
            self._tokenized.append(tokens)
            total_len += len(tokens)
            for tok in set(tokens):
                df[tok] = df.get(tok, 0) + 1
        self._avg_dl = total_len / N
        self._idf = {
            term: math.log((N - freq + 0.5) / (freq + 0.5) + 1)
            for term, freq in df.items()
        }

    def query(self, q: str, n: int = 5, min_score: float = 0.15) -> List[int]:
        if not self._docs:
            return []
        tokens = _tokenize(q)
        scores: List[tuple] = []
        for i, tok_doc in enumerate(self._tokenized):
            dl = len(tok_doc)
            counter = Counter(tok_doc)
            score = 0.0
            for tok in tokens:
                idf = self._idf.get(tok, 0.0)
                tf = counter.get(tok, 0)
                score += idf * (tf * (self.k1 + 1)) / (
                    tf + self.k1 * (1.0 - self.b + self.b * dl / max(self._avg_dl, 1))
                )
            scores.append((i, score))
        scores.sort(key=lambda x: x[1], reverse=True)
        return [i for i, s in scores[:n] if s >= min_score]


# ── Static security knowledge ─────────────────────────────────────────────────

_STATIC_KNOWLEDGE: List[Dict] = [
    {
        "source": "MITRE ATT&CK Tactics",
        "text": (
            "MITRE ATT&CK Tactics Overview:\n"
            "TA0001 Initial Access: Phishing, spear-phishing, drive-by compromise, valid accounts, "
            "external remote services, exploit public-facing applications.\n"
            "TA0002 Execution: Command shell, scripting (PowerShell, Python, bash), scheduled tasks, WMI, malicious macros.\n"
            "TA0003 Persistence: Registry run keys, scheduled tasks, startup folder, services, DLL hijacking, account creation.\n"
            "TA0004 Privilege Escalation: Vulnerability exploitation, token impersonation, sudo abuse, SUID binaries, UAC bypass.\n"
            "TA0005 Defense Evasion: Obfuscation, disable AV/EDR, log clearing, timestomping, LOLBins, masquerading, rootkits.\n"
            "TA0006 Credential Access: Keylogging, LSASS dump, SAM dump, Kerberoasting, pass-the-hash, brute force.\n"
            "TA0007 Discovery: Network scan (nmap), process/account enumeration, system info, file directory enumeration.\n"
            "TA0008 Lateral Movement: Pass-the-hash, pass-the-ticket, RDP, SMB/PsExec, WMI, SSH remote services.\n"
            "TA0009 Collection: Screen capture, keylogging, clipboard data, email collection, staged file archives.\n"
            "TA0010 Exfiltration: Over C2, web services, DNS tunneling, FTP, email, encrypted archive upload.\n"
            "TA0011 Command & Control: HTTP/S beaconing, DNS tunneling, domain fronting, fast-flux DNS, encrypted channels.\n"
            "TA0040 Impact: Ransomware, data wiping, service disruption, account lockout, firmware corruption, defacement."
        ),
    },
    {
        "source": "Brute Force Detection",
        "text": (
            "Brute Force Attack Detection and Response:\n"
            "Indicators: Multiple failed authentication attempts, rapid logins from single IP, credential stuffing patterns.\n"
            "Windows Event IDs: 4625 (failed logon), 4740 (account lockout), 4771 (Kerberos pre-auth failed).\n"
            "Linux: /var/log/auth.log repeated sshd/PAM failures. Wazuh rules: 5710, 5712, 5716.\n"
            "Thresholds: >5 failures/minute = suspicious; >20/minute = confirmed brute force.\n"
            "Response Steps:\n"
            "1. Identify source_ip from alert\n"
            "2. Check VT score — if malicious (>5), block via iptables immediately\n"
            "3. Wazuh active-response: firewall-drop for confirmed attack source\n"
            "4. Review targeted account for successful logon after failures\n"
            "5. Force password reset for targeted accounts\n"
            "6. Enable MFA on targeted accounts\n"
            "7. Consider account lockout policy enforcement"
        ),
    },
    {
        "source": "Ransomware Response",
        "text": (
            "Ransomware Incident Response:\n"
            "Indicators: Mass file encryption (.locked, .encrypted, .crypt, .ransom extensions), ransom note creation, "
            "shadow copy deletion (vssadmin delete shadows), high disk I/O, Wazuh rule 87105.\n"
            "Immediate Actions:\n"
            "1. ISOLATE affected system immediately — disconnect from all networks\n"
            "2. Do NOT reboot — memory may contain decryption artifacts\n"
            "3. Preserve disk image before any recovery attempts\n"
            "4. Identify patient zero — check first encrypted file timestamp\n"
            "5. Block lateral movement — isolate VLAN, disable SMB shares\n"
            "6. Identify ransomware family via VT hash lookup, ransom note content, file extension\n"
            "7. Check for persistence: scheduled tasks, registry run keys, startup entries\n"
            "8. Report to stakeholders — assess regulatory notification requirements\n"
            "9. Restore from verified clean backups after eradication\n"
            "IOC collection: ransomware binary hash, C2 IPs/domains, ransom note filename, encrypted file extension."
        ),
    },
    {
        "source": "Phishing Response",
        "text": (
            "Phishing and Credential Harvesting Response:\n"
            "Indicators: Suspicious email links, macro-enabled documents, fake login pages, new account creation after click.\n"
            "Detection: DNS requests to newly registered domains, PowerShell download cradles, HTTP POST to suspicious domains.\n"
            "Response Steps:\n"
            "1. Identify affected accounts from email/proxy logs\n"
            "2. Reset compromised passwords immediately\n"
            "3. Revoke all active sessions and OAuth tokens for affected accounts\n"
            "4. Block sender domain and IP at email gateway\n"
            "5. Search for lateral movement using harvested credentials\n"
            "6. Review MFA logs — were prompts accepted from unusual geolocations?\n"
            "7. Audit mailbox rules — check for forwarding rules created by attacker\n"
            "8. Revoke unauthorized OAuth app consent grants\n"
            "Indicators of post-phishing compromise: impossible travel alerts, OAuth app consent, new inbox rules, mass email access."
        ),
    },
    {
        "source": "Malware Analysis",
        "text": (
            "Malware Analysis and Classification:\n"
            "VirusTotal Score Interpretation: 0 = clean; 1-4 = suspicious; 5-15 = likely malicious; 15+ = confirmed malicious.\n"
            "Malware Types:\n"
            "- RAT (Remote Access Trojan): Persistent backdoor, keylogging, screen capture, webcam. Regular C2 beaconing.\n"
            "- Trojan Dropper: Appears legitimate, drops payload. Check Temp/AppData/Roaming directories.\n"
            "- Rootkit: Hides processes/files at kernel level. Requires offline forensic analysis.\n"
            "- Worm: Self-propagating via network shares, SMB (EternalBlue), email, USB.\n"
            "- Botnet Agent: DDoS participation, spam relay, crypto mining, receives C2 commands.\n"
            "- Spyware/Keylogger: Captures credentials, screenshots, clipboard. Exfiltrates periodically.\n"
            "Static Analysis: File hash (MD5/SHA1/SHA256), PE headers, imports, strings, packer detection.\n"
            "Dynamic Analysis: Process spawning, registry changes, network connections, file system modifications.\n"
            "IOC extraction: C2 IPs/domains from PCAP, dropped file hashes, registry persistence keys, mutexes."
        ),
    },
    {
        "source": "Network Reconnaissance Detection",
        "text": (
            "Network Scanning and Reconnaissance Detection:\n"
            "Port Scan Indicators: Wazuh rule 40101, SYN packets to multiple ports without response, Nmap fingerprints.\n"
            "Scan types: SYN scan (half-open), UDP scan, version scan (-sV), OS detection (-O).\n"
            "Thresholds: >100 ports/second = aggressive; >10 hosts in 60s = network sweep.\n"
            "DNS Reconnaissance: Zone transfer attempts (AXFR requests), PTR record enumeration, subdomain brute forcing.\n"
            "C2 Beaconing Patterns: Regular intervals (every N seconds), encrypted traffic to uncommon ports, "
            "HTTP/S POST with base64 encoded data, short sleep-then-callback cycles.\n"
            "DNS Tunneling Indicators: High query volume to single domain, DNS names >50 chars, "
            "non-standard record types (TXT/NULL/MX abuse), anomalously high DNS entropy.\n"
            "Response: Block scan source, correlate with auth events, check if scan preceded exploitation attempt."
        ),
    },
    {
        "source": "Lateral Movement Detection",
        "text": (
            "Lateral Movement Detection and Response:\n"
            "Common Techniques: PsExec, WMI execute, RDP hopping, Pass-the-Hash (PTH), Pass-the-Ticket (PTT), SMB traversal.\n"
            "Windows Events: 4624 type 3 (network logon), 4648 (explicit credential logon), "
            "7045 (new service installed remotely), 4697 (service creation in security log).\n"
            "Wazuh Rules: 18104 (PsExec detected), 60006 (RDP auth), SMB admin share access.\n"
            "Detection Signals: Admin tools on non-admin workstations, logons from unusual source IPs, "
            "ADMIN$/IPC$ share connections, new services created on remote hosts, scheduled task creation remotely.\n"
            "Response:\n"
            "1. Map movement path — which systems accessed in what order?\n"
            "2. Identify initial compromise (patient zero)\n"
            "3. Check if domain admin credentials used — if yes, full AD investigation required\n"
            "4. Segment and isolate all compromised systems\n"
            "5. Reset all potentially exposed account passwords including service accounts\n"
            "6. Rebuild compromised systems from clean image"
        ),
    },
    {
        "source": "Data Exfiltration Detection",
        "text": (
            "Data Exfiltration Detection and Response:\n"
            "Network Indicators: Large outbound transfers (>500MB to external IP), connections to file sharing APIs "
            "(Dropbox, MEGA, Google Drive, S3), encrypted blobs via HTTP POST, DNS tunneling exfil.\n"
            "Host Indicators: Archive creation (zip/rar/7z) in temp dirs before outbound transfer, rclone/MEGAsync execution, "
            "access to sensitive file shares outside business hours, bulk file access events.\n"
            "DLP Triggers: Mass email forwarding, USB large copy, cloud sync tool installation.\n"
            "Response:\n"
            "1. Block egress from affected system immediately\n"
            "2. Identify destination: IP geolocation, domain registration age, VT reputation\n"
            "3. Determine what data was accessed — file access logs, DLP alerts, FIM events\n"
            "4. Assess data sensitivity: PII, PHI, financial records, trade secrets, IP\n"
            "5. Trigger breach notification assessment if regulated data involved\n"
            "6. Preserve network captures and logs as forensic evidence\n"
            "7. Notify legal/compliance team immediately if regulated data confirmed exfiltrated"
        ),
    },
    {
        "source": "Privilege Escalation",
        "text": (
            "Privilege Escalation Detection and Response:\n"
            "Linux Techniques: SUID binary abuse (find / -perm /4000), sudo misconfiguration (sudo -l), "
            "writable cron job scripts, writable /etc/passwd, kernel exploits (dirty cow CVE-2016-5195, dirty pipe CVE-2022-0847), "
            "LD_PRELOAD injection, PATH hijacking, Docker socket abuse (/var/run/docker.sock).\n"
            "Windows Techniques: UAC bypass (eventvwr, fodhelper, sdclt), token impersonation (SeImpersonatePrivilege), "
            "DLL hijacking, unquoted service paths, AlwaysInstallElevated registry key, PrintSpoofer, JuicyPotato.\n"
            "Detection: Wazuh FIM alerts on /etc/sudoers and /etc/passwd, Windows Event 4672 (special privileges), "
            "4673 (privileged service called), unexpected SUID/GUID file changes.\n"
            "Response:\n"
            "1. Identify the exact escalation technique\n"
            "2. Check for persistence installed post-escalation (backdoors, new accounts)\n"
            "3. Audit all accounts active during compromise window\n"
            "4. Reset privileged account passwords (root, SYSTEM, domain admin)\n"
            "5. Patch the exploited vulnerability or misconfiguration"
        ),
    },
    {
        "source": "Incident Severity Classification",
        "text": (
            "Incident Severity Classification:\n"
            "CRITICAL: Active ransomware/wiper in progress, confirmed data exfiltration of sensitive data, "
            "domain admin compromise, critical infrastructure impact, zero-day exploitation, >50 systems affected, APT indicators.\n"
            "HIGH: Multi-system malware infection, credential dump (LSASS/NTDS), confirmed lateral movement, "
            "privileged account compromise, C2 communication established, active exploitation of known CVE.\n"
            "MEDIUM: Single malware infection (contained), brute force success on non-privileged account, "
            "phishing click without confirmed compromise, policy violation, anomalous behavior without confirmed attack.\n"
            "LOW: Failed attack attempts, reconnaissance only, single suspicious event without corroboration, "
            "informational Wazuh alerts, compliance warnings.\n"
            "Escalation Path: L1 SOC → handles Low/Medium with playbooks; "
            "L2 SOC → investigates High; Incident Responder → manages Critical/ransomware/APT/breach."
        ),
    },
    {
        "source": "IR Lifecycle NIST",
        "text": (
            "Incident Response Lifecycle (NIST SP 800-61):\n"
            "1. PREPARATION: Establish IR team/roles, document procedures, deploy detection tools, threat intel feeds, tabletop exercises.\n"
            "2. IDENTIFICATION/TRIAGE: Detect anomaly via SIEM/EDR/email, validate alert (TP vs FP), classify severity, "
            "assign case number, notify stakeholders.\n"
            "3. CONTAINMENT:\n"
            "   Short-term: Network isolate, block IP, disable user account, revoke tokens.\n"
            "   Long-term: Forensic image, patch/rebuild system, compensating controls.\n"
            "4. ERADICATION: Remove malware/backdoors, delete malicious artifacts, remove persistence, patch vulnerability, "
            "verify no attacker access remains.\n"
            "5. RECOVERY: Restore from verified clean backup, validate system integrity (hashes), "
            "return to production gradually, monitor closely for 30 days.\n"
            "6. LESSONS LEARNED: Root cause analysis (RCA), timeline reconstruction, gap identification, "
            "update playbooks and detection rules, stakeholder/executive report.\n"
            "Documentation requirements: event timeline, all actions taken, evidence list, chain of custody, affected assets."
        ),
    },
    {
        "source": "Windows Event IDs",
        "text": (
            "Critical Windows Security Event IDs:\n"
            "Authentication: 4624 (successful logon — type 3=network, type 10=remote), 4625 (failed logon), "
            "4634 (logoff), 4648 (logon with explicit credentials), 4672 (admin special privileges), 4740 (account lockout).\n"
            "Account Management: 4720 (account created), 4722 (enabled), 4724 (password reset), "
            "4728/4732 (added to security group), 4756 (added to universal group), 4738 (account changed).\n"
            "Process: 4688 (process created — enable command line auditing), 4689 (process terminated).\n"
            "Services: 7045 (new service installed), 7036 (service state change), 4697 (service installed via Security log).\n"
            "Scheduled Tasks: 4698 (task created), 4702 (updated), 4699 (deleted), 4700 (enabled).\n"
            "PowerShell: 4103 (module logging), 4104 (script block — captures deobfuscated code), 400/403 (engine state).\n"
            "RDP: 4778 (reconnect), 1149 (remote connection in TerminalServices log).\n"
            "Kerberos: 4768 (TGT requested), 4769 (service ticket requested — Kerberoasting uses RC4 encryption type 0x17)."
        ),
    },
    {
        "source": "Wazuh SOC Rules",
        "text": (
            "Wazuh SIEM Key Configuration:\n"
            "Critical Rule IDs: 5710/5712/5716 (auth failures SSH/Windows), 31108/31151 (web app attacks SQLi/XSS), "
            "87105 (ransomware indicators), 40101 (port scan), 18104 (PsExec usage), 60006 (RDP auth), "
            "550 (FIM file change), 591 (Windows firewall change), 5501 (new user created), 5402 (sudo success).\n"
            "Alert Levels: 0-3 informational; 4-7 low; 8-11 medium; 12-14 high; 15 critical.\n"
            "Active Response Actions: firewall-drop (blocks IP via iptables/Windows firewall), "
            "host-deny (/etc/hosts.deny), restart-service, custom scripts.\n"
            "FIM (File Integrity Monitoring): Watches critical paths — /etc/passwd, /etc/sudoers, "
            "Windows SAM/SYSTEM hives, web root directories.\n"
            "Wazuh API endpoints: GET /security/users, GET /agents, GET /rules, POST /active-response.\n"
            "Agent status: active, disconnected, never_connected, pending."
        ),
    },
    {
        "source": "TheHive Cortex Integration",
        "text": (
            "TheHive Case Management and Cortex Analyzers:\n"
            "TheHive: SOAR-integrated case management. Cases contain: observables (IOCs), tasks, timeline.\n"
            "Case severity: 1=Low, 2=Medium, 3=High, 4=Critical.\n"
            "Observable types: ip, domain, url, hash (md5/sha256), email, filename, user-agent, registry-key.\n"
            "Status flow: New → In Progress → Resolved → Closed.\n"
            "Cortex Analyzers:\n"
            "- VirusTotal_GetReport: Hash/IP/domain/URL reputation lookup\n"
            "- MaxMind_GeoIP: IP geolocation (country, ASN, org)\n"
            "- Shodan_Host: Open ports, services, CVEs for an IP\n"
            "- URLScan_Search: Website screenshot and behavior analysis\n"
            "- AbuseIPDB: IP abuse reporting database\n"
            "- DomainTools_WhoisHistory: Domain registration history\n"
            "- MISP_Search: Threat intel from MISP feeds\n"
            "Cortex Responders: Block IP via firewall, disable AD user account, send Slack/email notification.\n"
            "SentriX auto-creates TheHive cases for HIGH/CRITICAL incidents and auto-runs VT analysis on IOCs."
        ),
    },
    {
        "source": "SOC Triage Methodology",
        "text": (
            "SOC Alert Triage Methodology:\n"
            "Step 1 — Validate: Is this a true positive? Check alert source, rule logic, asset context, historical patterns.\n"
            "Step 2 — Enrich: Add context to all IOCs (VT score, GeoIP, WHOIS, threat intel feeds, asset criticality).\n"
            "Step 3 — Correlate: Link to other alerts from same source/target in last 24h. Check for campaign patterns.\n"
            "Step 4 — Classify: Apply severity matrix. Consider attack stage (recon vs active exploitation vs post-compromise).\n"
            "Step 5 — Contain: For HIGH/CRITICAL confirmed TP — initiate immediate containment: block IP, isolate host, disable account.\n"
            "Step 6 — Document: Create incident with full timeline, IOCs, evidence, actions taken, chain of custody.\n"
            "Step 7 — Escalate: L1→L2 for confirmed compromise; L2→IR team for critical/active threat.\n"
            "False Positive Reduction: Tune rules, whitelist known-good IPs and processes, add asset context.\n"
            "Alert Fatigue: Correlate related alerts into single incident, auto-close informational noise, prioritize by asset value."
        ),
    },
    {
        "source": "IOC Types and Handling",
        "text": (
            "Indicator of Compromise (IOC) Types and Handling:\n"
            "IP Address: Check VT, AbuseIPDB, Shodan, GeoIP. Block if VT score >5 or confirmed malicious.\n"
            "Domain/URL: Check VT, URLScan, WHOIS registration age. Flag newly registered domains (<30 days).\n"
            "File Hash (MD5/SHA1/SHA256): Submit to VT. SHA256 is preferred — MD5/SHA1 collision risk.\n"
            "Email: Check sender reputation, SPF/DKIM/DMARC validation, attachment hashes.\n"
            "Mutex: Unique malware signature — search across all endpoints for same mutex name.\n"
            "Registry Key: Persistence indicator — correlate with known malware IOC databases.\n"
            "User-Agent: Non-standard UAs indicate malware/tooling — cross-reference with known C2 frameworks.\n"
            "IOC Lifecycle: Add to TheHive observable → run Cortex analyzers → enrich with threat intel → "
            "block/monitor → expire after defined TTL (typically 30-90 days for dynamic IPs, indefinite for hashes).\n"
            "Threat Intel Sharing: STIX/TAXII format, MISP platform, ISACs (FS-ISAC, H-ISAC, etc.)."
        ),
    },
]


# ── KnowledgeBase class ───────────────────────────────────────────────────────

class KnowledgeBase:
    def __init__(self):
        self._bm25 = _BM25()
        self._sources: List[Dict] = []
        self._built = False

    def build(self, db=None) -> int:
        """Index static knowledge + DB incidents + playbooks. Returns doc count."""
        docs = list(_STATIC_KNOWLEDGE)

        if db is not None:
            docs.extend(self._load_incidents(db))
            docs.extend(self._load_playbooks(db))

        self._sources = docs
        self._bm25.fit([d["text"] for d in docs])
        self._built = True
        return len(docs)

    def _load_incidents(self, db) -> List[Dict]:
        try:
            from backend.models.incident import Incident
            incidents = (
                db.query(Incident)
                .filter(Incident.status.in_(["resolved", "closed"]))
                .order_by(Incident.created_at.desc())
                .limit(100)
                .all()
            )
            result = []
            for inc in incidents:
                parts = [
                    f"Past Incident: {inc.title}",
                    f"Case: {inc.case_number} | Severity: {inc.severity} | Status: {inc.status}",
                ]
                if inc.description:
                    parts.append(f"Description: {inc.description[:300]}")
                if inc.ai_summary:
                    parts.append(f"AI Summary: {inc.ai_summary[:400]}")
                if inc.ai_recommendations:
                    parts.append(f"Recommendations: {inc.ai_recommendations[:400]}")
                if inc.investigation_notes:
                    parts.append(f"Investigation Notes: {inc.investigation_notes[:300]}")
                result.append({
                    "source": f"Past Incident {inc.case_number}",
                    "text": "\n".join(parts),
                })
            return result
        except Exception:
            return []

    def _load_playbooks(self, db) -> List[Dict]:
        try:
            from backend.models.playbook import Playbook, PlaybookStep
            playbooks = db.query(Playbook).filter(Playbook.is_active == True).all()  # noqa: E712
            result = []
            for pb in playbooks:
                steps = (
                    db.query(PlaybookStep)
                    .filter(PlaybookStep.playbook_id == pb.id)
                    .order_by(PlaybookStep.step_order)
                    .all()
                )
                step_lines = [
                    f"  Step {s.step_order}: [{s.action_type}] {s.description or ''} "
                    f"(target: {s.target_field or s.target_override or 'N/A'})"
                    for s in steps
                ]
                text = "\n".join([
                    f"Playbook: {pb.name}",
                    f"Category: {pb.category or 'general'} | Built-in: {pb.is_builtin}",
                    f"Description: {pb.description or ''}",
                    "Steps:\n" + ("\n".join(step_lines) if step_lines else "  (no steps)"),
                ])
                result.append({"source": f"Playbook: {pb.name}", "text": text})
            return result
        except Exception:
            return []

    def retrieve(self, query: str, n: int = 4) -> str:
        """Return formatted context string of top-n relevant knowledge chunks."""
        if not self._built:
            return ""
        indices = self._bm25.query(query, n=n)
        if not indices:
            return ""
        lines = ["\n\n--- Relevant Knowledge Base Context ---"]
        for idx in indices:
            doc = self._sources[idx]
            lines.append(f"\n[{doc['source']}]\n{doc['text']}")
        lines.append("\n--- End Knowledge Base Context ---")
        return "\n".join(lines)

    @property
    def doc_count(self) -> int:
        return len(self._sources)


# ── Singleton ─────────────────────────────────────────────────────────────────

knowledge_base = KnowledgeBase()

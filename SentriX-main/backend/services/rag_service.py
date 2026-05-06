"""
RAG-based AI Engine for SentriX.
Uses LangChain + ChromaDB + OpenAI when configured.
Falls back to intelligent rule-based responses for demo.
"""
from typing import Optional, List, Tuple, Dict
from backend.config import settings

SYSTEM_PROMPT = """You are SentriX AI — an expert Virtual SOC Analyst powered by advanced threat intelligence.
You assist security analysts with:
- Incident analysis and investigation
- Identifying Indicators of Compromise (IOCs)
- Threat hunting and correlation
- Response recommendations and playbook guidance
- MITRE ATT&CK framework mapping

Always be precise, structured, and actionable. Format responses clearly with sections when appropriate.
When analyzing incidents, provide: Summary, IOCs found, Severity assessment, and Recommended actions."""


async def get_ai_response(
    query: str,
    history: List[Tuple[str, str]] = None,
    incident_context: Optional[Dict] = None,
    system_stats: Optional[Dict] = None
) -> str:
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return await _openai_rag_response(query, history or [], incident_context, system_stats)
    return _demo_response(query, incident_context, system_stats)


async def analyze_incident_with_rag(context: dict) -> dict:
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return await _openai_analyze_incident(context)
    return _demo_analyze_incident(context)


async def _openai_rag_response(query: str, history: list, incident_context: Optional[dict], system_stats: Optional[dict] = None) -> str:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.schema import HumanMessage, AIMessage, SystemMessage

        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            openai_api_key=settings.OPENAI_API_KEY,
            temperature=0.3,
            max_tokens=1024
        )

        extra_ctx = ""
        if system_stats:
            extra_ctx += _build_stats_context(system_stats)
        if incident_context:
            extra_ctx += f"\n\nCurrent Incident Context:\n"
            extra_ctx += f"Case: {incident_context.get('case_number', 'N/A')}\n"
            extra_ctx += f"Title: {incident_context.get('title', 'N/A')}\n"
            extra_ctx += f"Severity: {incident_context.get('severity', 'N/A')}\n"
            extra_ctx += f"Status: {incident_context.get('status', 'N/A')}\n"
            extra_ctx += f"Description: {incident_context.get('description', 'N/A')}\n"
            if incident_context.get("alerts"):
                extra_ctx += f"Related Alerts ({len(incident_context['alerts'])}):\n"
                for a in incident_context["alerts"]:
                    extra_ctx += f"  - [{a.get('severity','?').upper()}] {a.get('title','')} from {a.get('source_ip','unknown')}\n"
            if incident_context.get("iocs"):
                extra_ctx += f"IOCs ({len(incident_context['iocs'])}):\n"
                for i in incident_context["iocs"]:
                    extra_ctx += f"  - [{i.get('type','?').upper()}] {i.get('value','')} — {'MALICIOUS' if i.get('malicious') else 'clean'}\n"

        messages = [SystemMessage(content=SYSTEM_PROMPT + extra_ctx)]

        for role, content in history[-6:]:
            if role == "user":
                messages.append(HumanMessage(content=content))
            else:
                messages.append(AIMessage(content=content))

        messages.append(HumanMessage(content=query))
        response = await llm.ainvoke(messages)
        return response.content
    except Exception as e:
        return f"AI service error: {str(e)}. Using demo mode."


async def _openai_analyze_incident(context: dict) -> dict:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.schema import HumanMessage, SystemMessage

        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            openai_api_key=settings.OPENAI_API_KEY,
            temperature=0.2,
            max_tokens=2048
        )

        prompt = f"""Analyze the following security incident and provide a structured analysis.

Incident: {context['title']}
Severity: {context['severity']}
Description: {context.get('description', 'N/A')}

Related Alerts ({len(context.get('alerts', []))}):
{chr(10).join([f"- [{a['category']}] {a['title']} from {a.get('source_ip', 'unknown')}" for a in context.get('alerts', [])])}

IOCs found ({len(context.get('iocs', []))}):
{chr(10).join([f"- [{i['type']}] {i['value']} - {'MALICIOUS' if i['malicious'] else 'clean'} (VT: {i['score'] or 'N/A'})" for i in context.get('iocs', [])])}

Provide:
1. SUMMARY: A concise incident summary (2-3 sentences)
2. IOCs: Key indicators found and their significance
3. RECOMMENDATIONS: Specific response steps (numbered list)
4. MITRE ATT&CK: Relevant tactics/techniques if applicable"""

        response = await llm.ainvoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        text = response.content

        # Parse sections
        summary = _extract_section(text, "SUMMARY", "IOCs")
        iocs_text = _extract_section(text, "IOCs", "RECOMMENDATIONS")
        recommendations = _extract_section(text, "RECOMMENDATIONS", "MITRE")

        return {
            "summary": summary or text[:500],
            "iocs": iocs_text,
            "recommendations": recommendations,
            "full_analysis": text
        }
    except Exception as e:
        return _demo_analyze_incident(context)


def _build_stats_context(stats: dict) -> str:
    """Build a system stats section to inject into the AI prompt."""
    lines = ["\n\nLive SOC System Statistics (real-time from database):"]
    lines.append(f"- Total Alerts: {stats.get('total_alerts', 0)}")
    lines.append(f"  • Critical: {stats.get('critical_alerts', 0)}")
    lines.append(f"  • High: {stats.get('high_alerts', 0)}")
    lines.append(f"  • Medium: {stats.get('medium_alerts', 0)}")
    lines.append(f"  • Low: {stats.get('low_alerts', 0)}")
    lines.append(f"  • Open (unresolved): {stats.get('open_alerts', 0)}")
    lines.append(f"- Total Incidents: {stats.get('total_incidents', 0)}")
    lines.append(f"  • Open: {stats.get('open_incidents', 0)}")
    lines.append(f"  • In Progress: {stats.get('in_progress_incidents', 0)}")
    lines.append(f"  • Resolved: {stats.get('resolved_incidents', 0)}")
    lines.append(f"- Total IOCs tracked: {stats.get('total_iocs', 0)}")
    lines.append(f"  • Confirmed malicious: {stats.get('malicious_iocs', 0)}")
    lines.append("Use these exact numbers when the analyst asks about counts, totals, or statistics.")
    return "\n".join(lines)


def _extract_section(text: str, start_marker: str, end_marker: str) -> str:
    try:
        start = text.find(start_marker)
        if start == -1:
            return ""
        start = text.find("\n", start) + 1
        end = text.find(end_marker, start)
        if end == -1:
            end = len(text)
        return text[start:end].strip()
    except Exception:
        return ""


def _demo_response(query: str, incident_context: Optional[dict] = None, system_stats: Optional[dict] = None) -> str:
    """Intelligent demo responses when AI is not configured."""
    q = query.lower()

    if incident_context:
        ctx_prefix = f"[Analyzing {incident_context.get('case_number', 'incident')} - {incident_context.get('title', '')}]\n\n"
    else:
        ctx_prefix = ""

    # Answer count/statistics questions with real data
    if system_stats and any(w in q for w in [
        "how many", "كم", "count", "total", "number of", "عدد",
        "alerts", "incidents", "ioc", "critical", "open", "statistics", "stats", "overview"
    ]):
        s = system_stats
        sev_breakdown = ", ".join([f"{k}: {v}" for k, v in s.get("alerts_by_severity", {}).items()])
        status_breakdown = ", ".join([f"{k.replace('_',' ')}: {v}" for k, v in s.get("incidents_by_status", {}).items()])
        return f"""{ctx_prefix}**Live SOC Statistics**

**Alerts**
| Metric | Count |
|--------|-------|
| Total Alerts | **{s.get('total_alerts', 0)}** |
| Open (unresolved) | **{s.get('open_alerts', 0)}** |
| Critical | **{s.get('critical_alerts', 0)}** |
| High | **{s.get('high_alerts', 0)}** |
| Medium | **{s.get('medium_alerts', 0)}** |
| Low | **{s.get('low_alerts', 0)}** |

**Incidents**
| Metric | Count |
|--------|-------|
| Total Incidents | **{s.get('total_incidents', 0)}** |
| Open | **{s.get('open_incidents', 0)}** |
| In Progress | **{s.get('in_progress_incidents', 0)}** |
| Resolved | **{s.get('resolved_incidents', 0)}** |

**IOCs**
| Metric | Count |
|--------|-------|
| Total Tracked | **{s.get('total_iocs', 0)}** |
| Confirmed Malicious | **{s.get('malicious_iocs', 0)}** |

> Data pulled live from the SentriX database."""

    if any(w in q for w in ["ioc", "indicator", "hash", "ip", "domain", "url"]):
        return ctx_prefix + """**IOC Analysis**

Based on the incident context, here are key indicators to investigate:

**Network Indicators:**
- Unusual outbound connections to unknown external IPs
- DNS queries for recently registered domains
- HTTP/S traffic with suspicious user-agents

**Host Indicators:**
- Unusual process creation (especially cmd.exe, powershell.exe spawned by Office apps)
- Registry modifications in HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
- Files dropped in %TEMP% or %APPDATA% directories

**Recommended IOC Extraction Steps:**
1. Pull firewall logs for suspicious outbound IPs
2. Check DNS logs for C2 beaconing patterns
3. Run VirusTotal enrichment on all collected hashes and IPs

> **Note:** Configure your OpenAI API key to enable full RAG-powered AI analysis."""

    elif any(w in q for w in ["recommend", "response", "action", "contain", "mitigate", "remediat"]):
        return ctx_prefix + """**Response Recommendations**

**Immediate Actions (0-1 hour):**
1. **Isolate** the affected host(s) from the network
2. **Preserve** forensic evidence — capture memory dump and disk image
3. **Block** malicious IPs/domains at the firewall level
4. **Revoke** compromised credentials and force password reset

**Short-term Actions (1-24 hours):**
1. Conduct **threat hunting** across similar endpoints for lateral movement
2. Review **authentication logs** for unauthorized access
3. **Scan** environment for additional IOCs using EDR tools
4. **Notify** stakeholders and open a formal incident ticket

**Recovery Steps:**
1. Re-image compromised systems from clean backup
2. Apply relevant security patches
3. Update detection rules (SIEM/EDR) based on new IOCs
4. Conduct **post-incident review**

**MITRE ATT&CK Mapping:** T1059 (Command Execution), T1027 (Obfuscation), T1071 (C2 Communication)

> **Note:** Configure your OpenAI API key to enable context-aware recommendations."""

    elif any(w in q for w in ["summary", "what happened", "explain", "describe", "tell me about"]):
        return ctx_prefix + """**Incident Summary**

This appears to be a **multi-stage attack** involving initial access followed by lateral movement and data exfiltration attempts.

**Attack Chain:**
- **Initial Access:** Likely via phishing email or exploitation of internet-facing service
- **Execution:** Malicious payload executed on target endpoint
- **Persistence:** Registry/scheduled task created for persistence
- **C2 Communication:** Beaconing to external infrastructure detected
- **Impact:** Potential data theft or ransomware deployment

**Severity Assessment:** HIGH — immediate response required

**Key Findings:**
- Multiple affected hosts identified
- External C2 communication detected
- Credential theft tools observed

> **Note:** Enable OpenAI integration for precise, context-aware incident analysis using your real log data."""

    elif any(w in q for w in ["mitre", "att&ck", "ttp", "tactic", "technique"]):
        return ctx_prefix + """**MITRE ATT&CK Framework Mapping**

Based on the observed behaviors, the following TTPs are relevant:

| Tactic | Technique | ID |
|--------|-----------|-----|
| Initial Access | Phishing / Spearphishing | T1566 |
| Execution | PowerShell / Command-Line | T1059 |
| Persistence | Registry Run Keys | T1547.001 |
| Defense Evasion | Obfuscated Files/Info | T1027 |
| Credential Access | OS Credential Dumping | T1003 |
| Lateral Movement | Pass the Hash | T1550.002 |
| C&C | Web Protocols (HTTP/S) | T1071.001 |
| Exfiltration | Exfiltration over C2 | T1041 |

**Recommended Detections:**
- Monitor for PowerShell with encoded commands
- Alert on LSASS access by non-system processes
- Detect unusual scheduled task creation

> Enable OpenAI API for real-time ATT&CK mapping based on your specific alerts."""

    elif any(w in q for w in ["wazuh", "siem", "log", "rule", "alert"]):
        return """**SIEM / Wazuh Integration**

SentriX integrates with **Wazuh SIEM** to collect and correlate security events.

**To connect Wazuh:**
1. Set `WAZUH_URL`, `WAZUH_USER`, `WAZUH_PASSWORD` in your `.env` file
2. Set `WAZUH_ENABLED=true`
3. Restart the SentriX backend

**Key Wazuh Rule Categories:**
- **Level 10+**: High severity alerts (brute force, rootkits)
- **Level 7-9**: Medium severity (failed logins, suspicious processes)
- **Level 1-6**: Low severity (informational)

**Useful Wazuh Queries:**
```
data.win.eventdata.logonType:10 AND rule.level:>7
```

> Once connected, SentriX automatically pulls alerts and correlates them with incidents."""

    elif any(w in q for w in ["virustotal", "vt", "scan", "malicious", "reputation"]):
        return """**VirusTotal Integration**

SentriX can enrich IOCs (IPs, domains, URLs, file hashes) using **VirusTotal API**.

**To enable:**
1. Get a free API key from [virustotal.com](https://www.virustotal.com)
2. Set `VIRUSTOTAL_API_KEY=your_key` in `.env`
3. Set `VIRUSTOTAL_ENABLED=true`

**Supported IOC Types:**
| Type | Example |
|------|---------|
| IP Address | 192.168.1.100 |
| Domain | malicious-domain.com |
| URL | http://evil.com/payload |
| File Hash (MD5/SHA256) | 44d88612fea8... |

**Enrichment Process:**
1. Go to an incident → add IOCs
2. Click **Enrich with VirusTotal**
3. Results show detection score (e.g., 45/72) and malicious status

> Currently running in **demo mode** — configure API key for real enrichment."""

    elif any(w in q for w in ["hello", "hi ", "help", "what can you", "capabilities"]):
        return """**Welcome to SentriX AI — Virtual SOC Analyst**

I'm your AI-powered security assistant. Here's what I can help with:

**Incident Investigation**
- Analyze alerts and correlate events
- Generate incident summaries and timelines
- Map attacks to MITRE ATT&CK framework

**IOC Analysis**
- Identify Indicators of Compromise
- Interpret VirusTotal results
- Threat intelligence enrichment

**Response Guidance**
- Step-by-step containment procedures
- Recovery recommendations
- Playbook guidance for common attack types

**System Integration**
- Wazuh SIEM configuration help
- TheHive case management
- VirusTotal enrichment

**Try asking me:**
- *"Analyze the current incident"*
- *"What IOCs should I look for in a ransomware attack?"*
- *"Give me response recommendations for this incident"*
- *"Map this attack to MITRE ATT&CK"*

> **Pro Tip:** Set an OpenAI API key to unlock full AI-powered analysis with RAG context."""

    else:
        return ctx_prefix + f"""**SentriX AI Response**

You asked: *"{query}"*

As your Virtual SOC Analyst, I can help with:

- **Incident Analysis**: Describe the incident and I'll provide a detailed analysis
- **IOC Investigation**: Ask about specific IPs, domains, hashes, or URLs
- **Response Planning**: Request containment and remediation steps
- **Threat Intelligence**: Ask about attack patterns, TTPs, and threat actors
- **MITRE Mapping**: Map observed behaviors to ATT&CK techniques

**Example queries:**
- *"What are the IOCs for this incident?"*
- *"Give me response recommendations"*
- *"Explain what happened in this attack"*
- *"Map this to MITRE ATT&CK"*

> For context-aware analysis, open a specific incident and ask questions there.
> Enable OpenAI API integration for full RAG-powered responses."""


def _demo_analyze_incident(context: dict) -> dict:
    """Demo incident analysis when AI is not configured."""
    severity = context.get("severity", "medium")
    title = context.get("title", "Unknown Incident")
    alerts = context.get("alerts", [])
    iocs = context.get("iocs", [])
    malicious_count = sum(1 for i in iocs if i.get("malicious"))

    summary = f"""Security incident "{title}" has been detected with {severity.upper()} severity.
The incident involves {len(alerts)} related alert(s) and {len(iocs)} indicator(s) of compromise,
of which {malicious_count} have been confirmed malicious by VirusTotal analysis.
Immediate investigation and containment measures are recommended."""

    ioc_text = ""
    if iocs:
        lines = []
        for i in iocs:
            status = "MALICIOUS" if i.get("malicious") else "suspicious"
            lines.append(f"- [{i['type'].upper()}] {i['value']} — {status} (VT Score: {i.get('score') or 'not checked'})")
        ioc_text = "\n".join(lines)
    else:
        ioc_text = "No IOCs have been added to this incident yet. Use the IOC enrichment feature to add and analyze indicators."

    recommendations = """1. **Immediate Containment**: Isolate affected systems from the network to prevent lateral movement.
2. **Evidence Preservation**: Capture memory dumps and preserve logs before remediation.
3. **IOC Blocking**: Block all confirmed malicious IPs and domains at the perimeter firewall.
4. **Credential Review**: Audit and reset credentials for any affected accounts.
5. **Threat Hunting**: Search for similar IOCs across the entire environment using SIEM.
6. **Patch Assessment**: Identify and apply relevant security patches.
7. **Stakeholder Notification**: Notify the security team lead and relevant stakeholders.
8. **Post-Incident Review**: Schedule a lessons-learned session after resolution.

> Configure OpenAI API key for AI-generated, context-specific recommendations."""

    return {
        "summary": summary,
        "iocs": ioc_text,
        "recommendations": recommendations,
        "full_analysis": f"# Incident Analysis: {title}\n\n## Summary\n{summary}\n\n## IOCs\n{ioc_text}\n\n## Recommendations\n{recommendations}"
    }

"""
RAG-based AI Engine for SentriX.
Uses LangChain + ChromaDB + OpenAI when configured.
Requires OPENAI_API_KEY and AI_ENABLED=true in .env.
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
    return "AI Analyst not configured — set OPENAI_API_KEY and AI_ENABLED=true in .env to enable real analysis."


async def analyze_incident_with_rag(context: dict) -> dict:
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return await _openai_analyze_incident(context)
    msg = "AI Analyst not configured — set OPENAI_API_KEY and AI_ENABLED=true in .env."
    return {"summary": msg, "iocs": "", "recommendations": "", "full_analysis": msg}


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
        return f"AI service error: {str(e)}"


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
        msg = f"AI analysis error: {str(e)}"
        return {"summary": msg, "iocs": "", "recommendations": "", "full_analysis": msg}


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



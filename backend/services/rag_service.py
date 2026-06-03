"""
AI Engine for SentriX.
Primary:  Anthropic Claude  (ANTHROPIC_API_KEY in .env)
Fallback: OpenAI GPT        (OPENAI_API_KEY + AI_ENABLED=true in .env)
Demo:     Returns a helpful placeholder when no key is configured.
"""
from __future__ import annotations
from typing import AsyncGenerator, Dict, List, Optional, Tuple

from backend.config import settings

SYSTEM_PROMPT = """You are SentriX AI — an expert Virtual SOC Analyst embedded in a Security Operations Center platform.
You assist security analysts with:
- Incident analysis and triage investigation
- Identifying and explaining Indicators of Compromise (IOCs)
- Threat hunting, correlation, and pattern recognition
- Response recommendations and playbook guidance
- MITRE ATT&CK framework mapping
- Security tool configuration (Wazuh, TheHive, Cortex, VirusTotal)

Guidelines:
- Be precise, structured, and actionable.
- Format responses with markdown — use headers, bullet points, and code blocks where helpful.
- For incident analysis always include: Summary, Key IOCs, Severity Assessment, and Recommended Actions.
- When quoting IPs, hashes, or commands always use `inline code` formatting.
- Keep responses focused and relevant to SOC operations."""


def _active_provider() -> str:
    if settings.ANTHROPIC_API_KEY:
        return "claude"
    if settings.OPENAI_API_KEY and settings.AI_ENABLED:
        return "openai"
    return "demo"


# ── Public API ────────────────────────────────────────────────────────────────

async def get_ai_response(
    query: str,
    history: List[Tuple[str, str]] = None,
    incident_context: Optional[Dict] = None,
    system_stats: Optional[Dict] = None,
) -> str:
    provider = _active_provider()
    if provider == "claude":
        return await _claude_response(query, history or [], incident_context, system_stats)
    if provider == "openai":
        return await _openai_response(query, history or [], incident_context, system_stats)
    return (
        "**AI Analyst — Demo Mode**\n\n"
        "No AI provider is configured. To enable full AI analysis:\n\n"
        "1. Add `ANTHROPIC_API_KEY=your-key` to `.env`  _(recommended — Claude)_\n"
        "2. Or add `OPENAI_API_KEY=your-key` and `AI_ENABLED=true` to `.env`\n\n"
        "Then restart the server."
    )


async def get_ai_response_stream(
    query: str,
    history: List[Tuple[str, str]] = None,
    incident_context: Optional[Dict] = None,
    system_stats: Optional[Dict] = None,
) -> AsyncGenerator[str, None]:
    """Async generator that yields response text chunks for streaming."""
    provider = _active_provider()
    if provider == "claude":
        async for chunk in _claude_stream(query, history or [], incident_context, system_stats):
            yield chunk
    elif provider == "openai":
        # OpenAI fallback: yield full response as a single chunk
        text = await _openai_response(query, history or [], incident_context, system_stats)
        yield text
    else:
        yield (
            "**AI Analyst — Demo Mode**\n\n"
            "Add `ANTHROPIC_API_KEY=your-key` to `.env` and restart the server to enable Claude.\n\n"
            "Alternatively add `OPENAI_API_KEY` + `AI_ENABLED=true` for GPT-4o."
        )


async def analyze_incident_with_rag(context: dict) -> dict:
    provider = _active_provider()
    if provider == "claude":
        return await _claude_analyze_incident(context)
    if provider == "openai":
        return await _openai_analyze_incident(context)
    msg = "AI Analyst not configured — add ANTHROPIC_API_KEY to .env."
    return {"summary": msg, "iocs": "", "recommendations": "", "full_analysis": msg}


def get_active_model() -> str:
    """Return a display string for the active AI model."""
    provider = _active_provider()
    if provider == "claude":
        return f"Claude ({settings.ANTHROPIC_MODEL})"
    if provider == "openai":
        return f"GPT ({settings.OPENAI_MODEL})"
    return "Demo Mode"


# ── Context builders ──────────────────────────────────────────────────────────

def _build_stats_context(stats: dict) -> str:
    if not stats:
        return ""
    lines = ["\n\n--- Live SOC Statistics (real-time from database) ---"]
    lines.append(f"Alerts: {stats.get('total_alerts', 0)} total | {stats.get('open_alerts', 0)} open")
    lines.append(f"  Critical: {stats.get('critical_alerts', 0)} | High: {stats.get('high_alerts', 0)} | Medium: {stats.get('medium_alerts', 0)} | Low: {stats.get('low_alerts', 0)}")
    lines.append(f"Incidents: {stats.get('total_incidents', 0)} total | {stats.get('open_incidents', 0)} open | {stats.get('in_progress_incidents', 0)} in progress | {stats.get('resolved_incidents', 0)} resolved")
    lines.append(f"IOCs: {stats.get('total_iocs', 0)} tracked | {stats.get('malicious_iocs', 0)} confirmed malicious")
    lines.append("Use these exact numbers when the analyst asks about counts, totals, or statistics.")
    lines.append("--- End Statistics ---")
    return "\n".join(lines)


def _build_incident_context(ctx: dict) -> str:
    if not ctx:
        return ""
    lines = [f"\n\n--- Active Incident Context ---"]
    lines.append(f"Case: {ctx.get('case_number')} | Title: {ctx.get('title')}")
    lines.append(f"Severity: {ctx.get('severity', '').upper()} | Status: {ctx.get('status')}")
    if ctx.get("description"):
        lines.append(f"Description: {ctx['description'][:500]}")
    if ctx.get("alerts"):
        lines.append(f"Related Alerts ({len(ctx['alerts'])}):")
        for a in ctx["alerts"]:
            lines.append(f"  [{a.get('severity','?').upper()}] {a.get('title','')} — src: {a.get('source_ip','N/A')} | cat: {a.get('category','N/A')}")
    if ctx.get("iocs"):
        lines.append(f"IOCs ({len(ctx['iocs'])}):")
        for i in ctx["iocs"]:
            verdict = "MALICIOUS" if i.get("malicious") else "clean"
            score = f" VT:{i['score']}" if i.get("score") else ""
            lines.append(f"  [{i.get('type','?').upper()}] {i.get('value','')} — {verdict}{score}")
    lines.append("--- End Incident Context ---")
    return "\n".join(lines)


def _build_messages(history: List[Tuple[str, str]], query: str) -> list:
    messages = []
    for role, content in history[-8:]:
        messages.append({"role": role, "content": content})
    messages.append({"role": "user", "content": query})
    return messages


# ── Claude ────────────────────────────────────────────────────────────────────

async def _claude_system(query: str, system_stats, incident_context) -> str:
    system = SYSTEM_PROMPT
    system += _build_stats_context(system_stats or {})
    system += _build_incident_context(incident_context)
    from backend.services.knowledge_base import knowledge_base
    system += knowledge_base.retrieve(query)
    return system


async def _claude_response(query: str, history: list, incident_context, system_stats) -> str:
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        system = await _claude_system(query, system_stats, incident_context)
        messages = _build_messages(history, query)
        response = await client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=2048,
            system=system,
            messages=messages,
        )
        return response.content[0].text
    except Exception as e:
        return f"Claude API error: {e}"


async def _claude_stream(query: str, history: list, incident_context, system_stats) -> AsyncGenerator[str, None]:
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        system = await _claude_system(query, system_stats, incident_context)
        messages = _build_messages(history, query)
        async with client.messages.stream(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=2048,
            system=system,
            messages=messages,
        ) as stream:
            async for text in stream.text_stream:
                yield text
    except Exception as e:
        yield f"\n\n_Claude API error: {e}_"


async def _claude_analyze_incident(context: dict) -> dict:
    prompt = _build_analysis_prompt(context)
    try:
        import anthropic
        client = anthropic.AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = await client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            max_tokens=3000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
        )
        text = response.content[0].text
        return _parse_analysis(text)
    except Exception as e:
        msg = f"Claude analysis error: {e}"
        return {"summary": msg, "iocs": "", "recommendations": "", "full_analysis": msg}


# ── OpenAI (fallback) ─────────────────────────────────────────────────────────

async def _openai_response(query: str, history: list, incident_context, system_stats) -> str:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.schema import HumanMessage, AIMessage, SystemMessage

        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            openai_api_key=settings.OPENAI_API_KEY,
            temperature=0.3,
            max_tokens=1024,
        )
        system = SYSTEM_PROMPT + _build_stats_context(system_stats or {}) + _build_incident_context(incident_context)
        msgs = [SystemMessage(content=system)]
        for role, content in history[-6:]:
            msgs.append(HumanMessage(content=content) if role == "user" else AIMessage(content=content))
        msgs.append(HumanMessage(content=query))
        response = await llm.ainvoke(msgs)
        return response.content
    except Exception as e:
        return f"OpenAI API error: {e}"


async def _openai_analyze_incident(context: dict) -> dict:
    try:
        from langchain_openai import ChatOpenAI
        from langchain.schema import HumanMessage, SystemMessage

        llm = ChatOpenAI(
            model=settings.OPENAI_MODEL,
            openai_api_key=settings.OPENAI_API_KEY,
            temperature=0.2,
            max_tokens=2048,
        )
        prompt = _build_analysis_prompt(context)
        response = await llm.ainvoke([SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=prompt)])
        return _parse_analysis(response.content)
    except Exception as e:
        msg = f"OpenAI analysis error: {e}"
        return {"summary": msg, "iocs": "", "recommendations": "", "full_analysis": msg}


# ── Shared helpers ────────────────────────────────────────────────────────────

def _build_analysis_prompt(context: dict) -> str:
    alerts_text = "\n".join(
        f"- [{a['category']}] {a['title']} from {a.get('source_ip', 'unknown')}"
        for a in context.get("alerts", [])
    )
    iocs_text = "\n".join(
        f"- [{i['type']}] {i['value']} — {'MALICIOUS' if i['malicious'] else 'clean'} (VT: {i['score'] or 'N/A'})"
        for i in context.get("iocs", [])
    )
    return f"""Analyze this security incident and provide a structured response.

Incident: {context['title']}
Case: {context.get('case_number', 'N/A')}
Severity: {context['severity']}
Description: {context.get('description', 'N/A')}

Related Alerts ({len(context.get('alerts', []))}):
{alerts_text or 'None'}

IOCs found ({len(context.get('iocs', []))}):
{iocs_text or 'None'}

Provide:
1. SUMMARY: Concise incident summary (2-3 sentences)
2. IOCs: Key indicators and their significance
3. RECOMMENDATIONS: Specific numbered response steps
4. MITRE ATT&CK: Relevant tactics/techniques"""


def _parse_analysis(text: str) -> dict:
    def extract(start, end):
        try:
            s = text.find(start)
            if s == -1:
                return ""
            s = text.find("\n", s) + 1
            e = text.find(end, s)
            return text[s: e if e != -1 else len(text)].strip()
        except Exception:
            return ""

    return {
        "summary":         extract("SUMMARY", "IOCs"),
        "iocs":            extract("IOCs", "RECOMMENDATIONS"),
        "recommendations": extract("RECOMMENDATIONS", "MITRE"),
        "full_analysis":   text,
    }

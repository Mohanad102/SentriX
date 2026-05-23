"""
Automated SOC Workflow: Wazuh → VT Enrichment → Cortex Analysis → TheHive Case

Pipeline triggered for every new alert:
  1. VirusTotal enrichment of all IOCs
  2. Cortex analysis of public IPs and domains
  3. Auto-create TheHive case for high/critical alerts
"""
import asyncio
import ipaddress
import json

from backend.config import settings

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Severity threshold for auto-creating a TheHive case
AUTO_THEHIVE_THRESHOLD = "high"

# Preferred analyzers, in order of preference per data type
_ANALYZER_PREFS = {
    "ip":     ["VirusTotal", "AbuseIPDB", "Shodan"],
    "domain": ["VirusTotal", "URLhaus", "OTX"],
    "url":    ["VirusTotal", "URLhaus"],
    "hash":   ["VirusTotal", "MalwareBazaar"],
}


def _is_public_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


async def run_auto_workflow(alert_id: int) -> None:
    """Entry point: run the full automated pipeline for one alert."""
    from backend.database import SessionLocal
    from backend.models.alert import Alert

    db = SessionLocal()
    try:
        alert = db.query(Alert).filter(Alert.id == alert_id).first()
        if not alert:
            return

        tag = f"[Workflow:{alert.alert_id}]"
        print(f"{tag} Starting pipeline — severity={alert.severity.upper()} title={alert.title!r}")

        # Step 1: VirusTotal enrichment
        vt_summary = await _step_vt_enrich(db, alert, tag)
        db.refresh(alert)

        # Step 2: Cortex analysis of public observables
        cortex_findings = await _step_cortex_analyze(db, alert, tag)
        db.refresh(alert)

        # Step 3: TheHive case — only for high/critical
        if _SEVERITY_ORDER.get(alert.severity, 0) >= _SEVERITY_ORDER.get(AUTO_THEHIVE_THRESHOLD, 2):
            await _step_thehive_case(db, alert, vt_summary, cortex_findings, tag)
        else:
            print(f"{tag} Severity {alert.severity} below threshold — skipping TheHive auto-case")

    except Exception as e:
        print(f"[Workflow] Unhandled error for alert {alert_id}: {e}")
    finally:
        db.close()


# ── Step 1: VirusTotal ────────────────────────────────────────────────────────

async def _step_vt_enrich(db, alert, tag: str) -> dict:
    if not settings.VIRUSTOTAL_ENABLED:
        return {}
    try:
        from backend.services.virustotal_service import auto_enrich_alert
        await auto_enrich_alert(db, alert)
        print(f"{tag} VT done — malicious={alert.vt_malicious}")
        return {"malicious": alert.vt_malicious, "enriched": True}
    except Exception as e:
        print(f"{tag} VT error: {e}")
        return {}


# ── Step 2: Cortex ────────────────────────────────────────────────────────────

async def _step_cortex_analyze(db, alert, tag: str) -> list:
    if not settings.CORTEX_ENABLED:
        return []

    from backend.services.cortex_service import list_analyzers, run_analyzer, get_job

    # Collect public IP observables
    observables: list[tuple[str, str]] = []
    for ip in filter(None, [alert.source_ip, alert.dest_ip]):
        if _is_public_ip(ip):
            observables.append((ip, "ip"))

    if not observables:
        print(f"{tag} No public observables for Cortex")
        return []

    # Get available analyzers and build type → IDs map
    try:
        analyzers = await list_analyzers()
    except Exception as e:
        print(f"{tag} Cortex list_analyzers error: {e}")
        return []

    if not analyzers:
        print(f"{tag} No Cortex analyzers available")
        return []

    type_map: dict[str, list[str]] = {}
    for a in analyzers:
        for dt in a.get("dataTypeList", []):
            type_map.setdefault(dt, []).append(a["id"])

    def _pick(data_type: str) -> str | None:
        candidates = type_map.get(data_type, [])
        for pref in _ANALYZER_PREFS.get(data_type, []):
            for c in candidates:
                if pref.lower() in c.lower():
                    return c
        return candidates[0] if candidates else None

    # Submit jobs
    submitted: list[dict] = []
    for value, data_type in observables:
        analyzer_id = _pick(data_type)
        if not analyzer_id:
            print(f"{tag} No analyzer available for {data_type}")
            continue
        try:
            job = await run_analyzer(analyzer_id, value, data_type)
            if job:
                jid = job.get("id") or job.get("_id")
                if jid:
                    submitted.append({"job_id": jid, "observable": value, "data_type": data_type, "analyzer": analyzer_id})
                    print(f"{tag} Cortex job {jid} submitted: {analyzer_id} on {value}")
        except Exception as e:
            print(f"{tag} Cortex submit error ({value}): {e}")

    if not submitted:
        return []

    # Persist job IDs on alert
    try:
        alert.cortex_jobs = json.dumps([j["job_id"] for j in submitted])
        db.commit()
    except Exception:
        pass

    # Poll results — max 90 s (18 × 5 s)
    findings: list[dict] = []
    pending = list(submitted)
    for _ in range(18):
        if not pending:
            break
        await asyncio.sleep(5)
        still_pending = []
        for entry in pending:
            try:
                job = await get_job(entry["job_id"])
                if not job:
                    still_pending.append(entry)
                    continue
                status = job.get("status", "")
                if status == "Success":
                    report = job.get("report", {})
                    findings.append({
                        "observable": entry["observable"],
                        "data_type":  entry["data_type"],
                        "analyzer":   entry["analyzer"],
                        "status":     "Success",
                        "summary":    _extract_summary(report),
                    })
                    print(f"{tag} Cortex job {entry['job_id']} succeeded: {findings[-1]['summary']}")
                elif status in ("Failure", "Failed"):
                    findings.append({
                        "observable": entry["observable"],
                        "data_type":  entry["data_type"],
                        "analyzer":   entry["analyzer"],
                        "status":     "Failure",
                        "summary":    "Analysis failed",
                    })
                    print(f"{tag} Cortex job {entry['job_id']} failed")
                else:
                    still_pending.append(entry)
            except Exception:
                still_pending.append(entry)
        pending = still_pending

    # Mark any still-running jobs as Pending
    for entry in pending:
        findings.append({
            "observable": entry["observable"],
            "data_type":  entry["data_type"],
            "analyzer":   entry["analyzer"],
            "status":     "Pending",
            "summary":    "Job still running — check Cortex UI",
        })

    return findings


def _extract_summary(report: dict) -> str:
    """Pull a human-readable one-liner from a Cortex job report."""
    if not report:
        return "No report data"

    # VirusTotal nested structure
    full = report.get("full", {})
    if isinstance(full, dict):
        stats = full.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        if stats:
            mal = stats.get("malicious", 0)
            total = sum(stats.values())
            return f"{mal}/{total} engines flagged malicious"

    # Taxonomy-style (many Cortex analyzers)
    taxonomies = report.get("summary", {}).get("taxonomies", []) if isinstance(report.get("summary"), dict) else []
    if taxonomies:
        t = taxonomies[0]
        return f"{t.get('namespace','')}/{t.get('predicate','')}={t.get('value','')}"

    for key in ["message", "errorMessage"]:
        val = report.get(key)
        if val:
            return str(val)[:200]

    return "See Cortex for full report"


# ── Step 3: TheHive ───────────────────────────────────────────────────────────

async def _step_thehive_case(db, alert, vt_summary: dict, cortex_findings: list, tag: str) -> None:
    if not settings.THEHIVE_ENABLED:
        print(f"{tag} TheHive disabled — skipping auto-case")
        return
    if alert.thehive_case_id:
        print(f"{tag} TheHive case already exists ({alert.thehive_case_id}) — skipping")
        return

    from backend.services.thehive_service import create_case, SEVERITY_MAP

    description = _build_case_description(alert, vt_summary, cortex_findings)
    tags = ["sentrix", "auto", alert.source or "wazuh", alert.severity]
    if alert.vt_malicious:
        tags.append("malicious")

    try:
        case = await create_case(
            title=f"[{alert.severity.upper()}] {alert.title}",
            description=description,
            severity=SEVERITY_MAP.get(alert.severity, 2),
            tags=tags,
        )
        if case:
            case_id = str(case.get("_id") or case.get("id") or "")
            if case_id:
                alert.thehive_case_id = case_id
                db.commit()
                print(f"{tag} TheHive case created: {case_id}")
        else:
            print(f"{tag} TheHive create_case returned None")
    except Exception as e:
        print(f"{tag} TheHive case creation error: {e}")


def _build_case_description(alert, vt_summary: dict, cortex_findings: list) -> str:
    lines = [
        f"## Alert: {alert.title}",
        "",
        "| Field | Value |",
        "|-------|-------|",
        f"| Alert ID | `{alert.alert_id}` |",
        f"| Severity | **{alert.severity.upper()}** |",
        f"| Source | {alert.source} |",
        f"| Rule ID | {alert.rule_id or 'N/A'} |",
        f"| Rule Level | {alert.rule_level or 'N/A'} |",
        f"| Category | {alert.category or 'N/A'} |",
        f"| Source IP | {alert.source_ip or 'N/A'} |",
        f"| Destination IP | {alert.dest_ip or 'N/A'} |",
        f"| Hostname | {alert.hostname or 'N/A'} |",
        "",
        "## Description",
        "",
        alert.description or "No description provided.",
        "",
    ]

    if vt_summary:
        verdict = "MALICIOUS IOCs detected" if vt_summary.get("malicious") else "No malicious IOCs found"
        icon = "⚠️" if vt_summary.get("malicious") else "✅"
        lines += [
            "## VirusTotal Enrichment",
            "",
            f"**Result:** {icon} {verdict}",
            "",
        ]

    if cortex_findings:
        lines += ["## Cortex Analyzer Results", ""]
        for f in cortex_findings:
            if f["status"] == "Success":
                summary = f["summary"]
                # Detect malicious signal in summary (e.g. "5/90 engines flagged")
                try:
                    mal_count = int(summary.split("/")[0])
                    icon = "⚠️" if mal_count > 0 else "✅"
                except (ValueError, IndexError):
                    icon = "✅"
            elif f["status"] == "Failure":
                icon = "❌"
            else:
                icon = "⏳"
            lines.append(
                f"- **{f['observable']}** ({f.get('data_type','')}) "
                f"via `{f['analyzer']}`: {icon} {f['summary']}"
            )
        lines.append("")

    lines += [
        "---",
        "*Auto-created by SentriX SOC Platform*",
    ]
    return "\n".join(lines)

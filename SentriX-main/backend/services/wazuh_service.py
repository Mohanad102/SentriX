"""
Wazuh SIEM Integration Service.
Fetches alerts from Wazuh API when enabled, otherwise uses mock data.
"""
import httpx
from typing import List, Dict
from backend.config import settings
import ssl


async def fetch_wazuh_alerts(limit: int = 50) -> List[Dict]:
    if not settings.WAZUH_ENABLED:
        return []
    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            # Authenticate
            auth_resp = await client.post(
                f"{settings.WAZUH_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD)
            )
            if auth_resp.status_code != 200:
                return []
            token = auth_resp.json()["data"]["token"]

            # Fetch alerts
            headers = {"Authorization": f"Bearer {token}"}
            alerts_resp = await client.get(
                f"{settings.WAZUH_URL}/alerts",
                headers=headers,
                params={"limit": limit, "sort": "-timestamp"}
            )
            if alerts_resp.status_code == 200:
                return alerts_resp.json().get("data", {}).get("affected_items", [])
    except Exception as e:
        print(f"Wazuh connection error: {e}")
    return []


def wazuh_alert_to_sentrix(wazuh_alert: Dict) -> Dict:
    """Convert Wazuh alert format to SentriX alert format."""
    rule = wazuh_alert.get("rule", {})
    agent = wazuh_alert.get("agent", {})
    level = rule.get("level", 0)

    if level >= 13:
        severity = "critical"
    elif level >= 10:
        severity = "high"
    elif level >= 7:
        severity = "medium"
    else:
        severity = "low"

    return {
        "alert_id": wazuh_alert.get("id", ""),
        "title": rule.get("description", "Unknown Alert"),
        "description": str(wazuh_alert.get("full_log", "")),
        "severity": severity,
        "source": "wazuh",
        "source_ip": wazuh_alert.get("data", {}).get("srcip"),
        "dest_ip": wazuh_alert.get("data", {}).get("dstip"),
        "hostname": agent.get("name"),
        "rule_id": str(rule.get("id", "")),
        "rule_level": level,
        "category": rule.get("groups", ["unknown"])[0] if rule.get("groups") else None,
        "raw_data": str(wazuh_alert)
    }

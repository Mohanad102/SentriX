from fastapi import APIRouter, Depends, HTTPException
from backend.utils.auth import get_current_user
from backend.config import settings
import httpx

router = APIRouter(prefix="/api/agents", tags=["agents"])


async def _wazuh_get(path: str) -> dict:
    """Make an authenticated GET request to the Wazuh API."""
    if not settings.WAZUH_ENABLED:
        raise HTTPException(status_code=503, detail="Wazuh integration is disabled")

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            auth = await client.post(
                f"{settings.WAZUH_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD)
            )
            if auth.status_code != 200:
                raise HTTPException(status_code=502, detail="Wazuh authentication failed")

            token = auth.json()["data"]["token"]
            resp = await client.get(
                f"{settings.WAZUH_URL}{path}",
                headers={"Authorization": f"Bearer {token}"}
            )
            if resp.status_code != 200:
                raise HTTPException(status_code=resp.status_code, detail="Wazuh API error")
            return resp.json()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Cannot reach Wazuh: {str(e)}")


@router.get("")
async def list_agents(
    status: str = "",
    limit: int = 500,
    current_user=Depends(get_current_user)
):
    params = f"?limit={limit}&sort=-dateAdd"
    if status:
        params += f"&status={status}"

    data = await _wazuh_get(f"/agents{params}")
    agents = data.get("data", {}).get("affected_items", [])

    result = []
    for a in agents:
        result.append({
            "id":           a.get("id"),
            "name":         a.get("name"),
            "ip":           a.get("ip"),
            "os":           _os_label(a.get("os", {})),
            "os_platform":  a.get("os", {}).get("platform", "unknown"),
            "status":       a.get("status"),
            "version":      a.get("version"),
            "last_keepalive": a.get("lastKeepAlive"),
            "date_add":     a.get("dateAdd"),
            "group":        ", ".join(a.get("group") or []) or "default",
            "node_name":    a.get("node_name"),
        })

    total       = data.get("data", {}).get("total_affected_items", len(result))
    active      = sum(1 for a in result if a["status"] == "active")
    disconnected = sum(1 for a in result if a["status"] == "disconnected")
    never_connected = sum(1 for a in result if a["status"] == "never_connected")

    return {
        "agents": result,
        "total": total,
        "active": active,
        "disconnected": disconnected,
        "never_connected": never_connected,
    }


@router.get("/summary")
async def agents_summary(current_user=Depends(get_current_user)):
    data = await _wazuh_get("/agents/summary/status")
    summary = data.get("data", {})
    return {
        "active":           summary.get("active", 0),
        "disconnected":     summary.get("disconnected", 0),
        "never_connected":  summary.get("never_connected", 0),
        "pending":          summary.get("pending", 0),
        "total":            summary.get("total_affected_items", 0),
    }


@router.get("/{agent_id}")
async def get_agent(agent_id: str, current_user=Depends(get_current_user)):
    data = await _wazuh_get(f"/agents?agents_list={agent_id}")
    items = data.get("data", {}).get("affected_items", [])
    if not items:
        raise HTTPException(status_code=404, detail="Agent not found")
    a = items[0]
    return {
        "id":             a.get("id"),
        "name":           a.get("name"),
        "ip":             a.get("ip"),
        "os":             _os_label(a.get("os", {})),
        "os_platform":    a.get("os", {}).get("platform", "unknown"),
        "status":         a.get("status"),
        "version":        a.get("version"),
        "last_keepalive": a.get("lastKeepAlive"),
        "date_add":       a.get("dateAdd"),
        "group":          ", ".join(a.get("group") or []) or "default",
        "node_name":      a.get("node_name"),
        "manager":        a.get("manager"),
        "register_ip":    a.get("registerIP"),
    }


@router.delete("/{agent_id}")
async def remove_agent(agent_id: str, current_user=Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")

    try:
        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            auth = await client.post(
                f"{settings.WAZUH_URL}/security/user/authenticate",
                auth=(settings.WAZUH_USER, settings.WAZUH_PASSWORD)
            )
            token = auth.json()["data"]["token"]
            resp = await client.delete(
                f"{settings.WAZUH_URL}/agents",
                headers={"Authorization": f"Bearer {token}"},
                params={"agents_list": agent_id, "status": "all", "older_than": "0s"}
            )
            return {"success": resp.status_code == 200}
    except Exception as e:
        raise HTTPException(status_code=503, detail=str(e))


def _os_label(os: dict) -> str:
    if not os:
        return "Unknown"
    name    = os.get("name", "")
    version = os.get("version", "")
    arch    = os.get("arch", "")
    return f"{name} {version} {arch}".strip() or "Unknown"

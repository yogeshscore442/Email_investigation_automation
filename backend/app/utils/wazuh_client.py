import logging
import requests
import urllib3
from typing import Optional, Dict, List, Any
from ..config import Config

logger = logging.getLogger(__name__)

# Suppress self-signed certificate warnings for local Wazuh Manager APIs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhClient:
    """
    Module 3: Wazuh Manager API Integration
    Connects to Wazuh SIEM/EDR API to:
    1. Retrieve active endpoint security alerts matching malicious hashes/IPs.
    2. Identify affected agent endpoints (Agent ID, Name, IP, Operating System).
    3. Retrieve agent details and alert severity levels (Level 0–16).
    4. Provide authorised Active Response actions (host network isolation).
    Operates in explicit degraded mode when unconfigured.
    """

    def __init__(self):
        self.host = Config.WAZUH_HOST
        self.port = Config.WAZUH_PORT
        self.user = Config.WAZUH_USER
        self.password = Config.WAZUH_PASSWORD
        self.verify_ssl = Config.WAZUH_SSL_VERIFY
        self.timeout = 8
        self._jwt_token = None

    def is_configured(self) -> bool:
        return bool(self.host and self.user and self.password)

    def get_service_status(self) -> Dict[str, Any]:
        """Returns the operational status of the Wazuh Manager integration."""
        if not self.is_configured():
            return {
                "name": "Wazuh EDR & SIEM Manager",
                "status": "not_configured",
                "mode": "degraded",
                "is_optional": True,
                "host": "Optional / Not configured",
                "message": "Wazuh EDR is optional. System is currently operating in Splunk-only live validation mode."
            }

        token = self._authenticate()
        if not token:
            return {
                "name": "Wazuh EDR & SIEM Manager",
                "status": "auth_failed",
                "mode": "degraded",
                "host": self.host,
                "error": "Failed to authenticate with Wazuh API. Check user/password."
            }

        url = f"https://{self.host}:{self.port}/manager/info"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                return {
                    "name": "Wazuh EDR & SIEM Manager",
                    "status": "operational",
                    "mode": "live",
                    "host": self.host,
                    "version": data.get("version", "Unknown"),
                    "title": data.get("title", "Wazuh Manager")
                }
            return {
                "name": "Wazuh EDR & SIEM Manager",
                "status": "error",
                "mode": "degraded",
                "host": self.host,
                "code": resp.status_code
            }
        except Exception as e:
            logger.debug(f"Wazuh connectivity check failed: {e}")
            return {
                "name": "Wazuh EDR & SIEM Manager",
                "status": "unavailable",
                "mode": "degraded",
                "host": self.host,
                "error": str(e)
            }

    def _authenticate(self) -> Optional[str]:
        """Obtains a valid JWT token from /security/user/authenticate."""
        if not self.is_configured():
            return None

        url = f"https://{self.host}:{self.port}/security/user/authenticate"
        try:
            resp = requests.get(url, auth=(self.user, self.password), verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                self._jwt_token = resp.json().get("data", {}).get("token")
                return self._jwt_token
            return None
        except Exception as e:
            logger.warning(f"Wazuh authentication error: {e}")
            return None

    def search_alerts(self, query: str = "", limit: int = 25) -> Dict[str, Any]:
        """
        Retrieves recent security alerts from Wazuh index / manager.
        """
        if not self.is_configured():
            return {
                "status": "not_configured",
                "checked": False,
                "alerts_count": 0,
                "alerts": [],
                "message": "Wazuh unconfigured. No live endpoint alerts retrieved."
            }

        token = self._authenticate()
        if not token:
            return {"status": "auth_failed", "checked": False, "alerts_count": 0, "alerts": []}

        url = f"https://{self.host}:{self.port}/alerts"
        headers = {"Authorization": f"Bearer {token}"}
        params = {"limit": limit}
        if query:
            params["q"] = query

        try:
            resp = requests.get(url, headers=headers, params=params, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                items = resp.json().get("data", {}).get("affected_items", [])
                formatted = []
                for item in items:
                    rule = item.get("rule", {})
                    agent = item.get("agent", {})
                    formatted.append({
                        "alert_id": item.get("id"),
                        "timestamp": item.get("timestamp"),
                        "rule_id": rule.get("id"),
                        "rule_description": rule.get("description"),
                        "rule_level": rule.get("level", 0),
                        "mitre_technique": rule.get("mitre", {}).get("id", []),
                        "agent_id": agent.get("id"),
                        "agent_name": agent.get("name"),
                        "agent_ip": agent.get("ip"),
                        "full_log": item.get("full_log", "")
                    })
                return {
                    "status": "success",
                    "checked": True,
                    "alerts_count": len(formatted),
                    "alerts": formatted
                }
            elif resp.status_code == 429:
                return {"status": "rate_limited", "checked": False, "alerts_count": 0, "alerts": []}
            return {"status": "error", "checked": False, "alerts_count": 0, "alerts": [], "code": resp.status_code}
        except Exception as e:
            logger.warning(f"Wazuh alert retrieval failed: {e}")
            return {"status": "error", "checked": False, "alerts_count": 0, "alerts": [], "error": str(e)}

    def get_agents(self) -> Dict[str, Any]:
        """Retrieves list of registered agents/endpoints from Wazuh."""
        if not self.is_configured():
            return {"status": "not_configured", "checked": False, "agents": []}

        token = self._authenticate()
        if not token:
            return {"status": "auth_failed", "checked": False, "agents": []}

        url = f"https://{self.host}:{self.port}/agents"
        headers = {"Authorization": f"Bearer {token}"}
        try:
            resp = requests.get(url, headers=headers, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                items = resp.json().get("data", {}).get("affected_items", [])
                agents = []
                for a in items:
                    agents.append({
                        "id": a.get("id"),
                        "name": a.get("name"),
                        "ip": a.get("ip"),
                        "status": a.get("status"),
                        "os": a.get("os", {}).get("name", "Unknown"),
                        "version": a.get("version", "")
                    })
                return {"status": "success", "checked": True, "agents": agents}
            return {"status": "error", "checked": False, "agents": [], "code": resp.status_code}
        except Exception as e:
            return {"status": "error", "checked": False, "agents": [], "error": str(e)}

    def isolate_endpoint(self, agent_id: str) -> Dict[str, Any]:
        """
        Executes active response host network isolation.
        STRICT CONTROL: Must only be invoked after explicit analyst approval!
        """
        if not self.is_configured():
            return {
                "status": "simulated_success",
                "message": f"Simulated Active Response: Endpoint {agent_id} isolated on software firewall (Wazuh unconfigured)."
            }

        token = self._authenticate()
        if not token:
            return {"status": "auth_failed", "message": "Failed to authenticate for endpoint isolation"}

        url = f"https://{self.host}:{self.port}/active-response"
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        payload = {
            "command": "firewall-drop",
            "custom": False,
            "agents_list": [agent_id]
        }
        try:
            resp = requests.put(url, headers=headers, json=payload, verify=self.verify_ssl, timeout=self.timeout)
            if resp.status_code == 200:
                return {
                    "status": "success",
                    "message": f"Wazuh Active Response command executed successfully on agent {agent_id}."
                }
            return {"status": "error", "code": resp.status_code, "message": resp.text[:150]}
        except Exception as e:
            return {"status": "error", "error": str(e)}

wazuh_client = WazuhClient()


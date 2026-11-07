import re
from abc import ABC, abstractmethod
from ..config import Config

class BaseRule(ABC):
    """Abstract base class for modular detection rules."""
    rule_id: str
    rule_name: str
    severity: str  # info, low, medium, high, critical
    category: str  # auth, identity, url, attachment, content, headers
    weight: int    # weight contribution to risk scoring

    @abstractmethod
    def evaluate(self, context: dict) -> dict:
        """
        Evaluates the parsed email context.
        Returns None if not triggered, or dict with {
            'rule_id': self.rule_id,
            'rule_name': self.rule_name,
            'severity': self.severity,
            'category': self.category,
            'weight': self.weight,
            'description': '...',
            'evidence': '...'
        }
        """
        pass

# ==================== Authentication & Identity Rules ====================

class RuleAuthDMARCFail(BaseRule):
    rule_id = "RULE_AUTH_DMARC_FAIL"
    rule_name = "DMARC Policy Failure"
    severity = "medium"
    category = "auth"
    weight = 15

    def evaluate(self, ctx: dict) -> dict:
        auth = ctx.get("auth", {})
        if auth.get("dmarc_status") == "fail":
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "The email explicitly failed the sender domain's DMARC policy check.",
                "evidence": f"DMARC status: fail ({auth.get('dmarc_details') or 'Alignment or SPF/DKIM check failed'})"
            }
        return None

class RuleAuthSPFFail(BaseRule):
    rule_id = "RULE_AUTH_SPF_FAIL"
    rule_name = "SPF Authentication Failure / Softfail"
    severity = "low"
    category = "auth"
    weight = 10

    def evaluate(self, ctx: dict) -> dict:
        auth = ctx.get("auth", {})
        spf = auth.get("spf_status")
        if spf in ["fail", "softfail"]:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": f"The transmitting mail server is not authorized under the domain's SPF record ({spf}).",
                "evidence": f"SPF evaluation result: {spf}. Details: {auth.get('spf_details', '')}"
            }
        return None

class RuleSenderReplyToMismatch(BaseRule):
    rule_id = "RULE_SENDER_REPLYTO_MISMATCH"
    rule_name = "Sender and Reply-To Address Discrepancy"
    severity = "medium"
    category = "identity"
    weight = 20

    def evaluate(self, ctx: dict) -> dict:
        headers_info = ctx.get("headers_info", {})
        if headers_info.get("sender_reply_mismatch"):
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "The sender header and Reply-To header specify different email addresses, commonly used to divert victim responses in BEC.",
                "evidence": headers_info.get("mismatch_details", "")
            }
        return None

class RuleDisplayNameSpoofing(BaseRule):
    rule_id = "RULE_DISPLAY_NAME_SPOOFING"
    rule_name = "Display Name Impersonation / Free Mail Spoofing"
    severity = "high"
    category = "identity"
    weight = 30

    def evaluate(self, ctx: dict) -> dict:
        headers_info = ctx.get("headers_info", {})
        from_name = headers_info.get("from_name", "").lower()
        from_domain = headers_info.get("from_domain", "").lower()
        
        # Check if display name claims a target brand but domain is a generic freemail or unrelated
        for brand in Config.TARGETED_BRANDS:
            if brand in from_name and brand not in from_domain:
                return {
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "severity": self.severity,
                    "category": self.category,
                    "weight": self.weight,
                    "description": f"Sender display name implies official affiliation with '{brand.capitalize()}', but email originated from unrelated domain '{from_domain}'.",
                    "evidence": f"Display Name: '{headers_info.get('from_name')}' | Actual Address: '{headers_info.get('from_email')}'"
                }
        return None

class RuleLookalikeDomain(BaseRule):
    rule_id = "RULE_LOOKALIKE_DOMAIN"
    rule_name = "Sender Domain Typosquatting / Lookalike Impersonation"
    severity = "high"
    category = "identity"
    weight = 35

    def evaluate(self, ctx: dict) -> dict:
        domain_intel = ctx.get("domain_intel", {})
        if domain_intel.get("is_lookalike"):
            brand = domain_intel.get("targeted_brand", "known organization")
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": f"The sender's domain exhibits syntactic or structural similarity to '{brand.capitalize()}', indicating deceptive typosquatting.",
                "evidence": f"Investigated domain: '{domain_intel.get('domain')}' targeting '{brand}' (Similarity: {domain_intel.get('similarity_score')})"
            }
        return None

# ==================== URL Investigation Rules ====================

class RuleMaliciousUrl(BaseRule):
    rule_id = "RULE_MALICIOUS_URL_DETECTED"
    rule_name = "Malicious or Suspicious URL Identified"
    severity = "critical"
    category = "url"
    weight = 40

    def evaluate(self, ctx: dict) -> dict:
        urls = ctx.get("urls", [])
        malicious_hits = []
        for u in urls:
            flags = u.get("detection_flags", [])
            for flag in flags:
                if flag.get("severity") in ["critical", "high"]:
                    malicious_hits.append(f"{flag['type']}: {u['defanged_url']} ({flag['message']})")
            if u.get("vt_reputation") in ["malicious", "suspicious"]:
                malicious_hits.append(f"VirusTotal {u.get('vt_reputation')}: {u['defanged_url']}")

        if malicious_hits:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "One or more links in the email body match high-risk phishing signatures, IP hosts, or known threat intel detections.",
                "evidence": " | ".join(malicious_hits[:3])
            }
        return None

# ==================== Attachment Forensics Rules ====================

class RuleMacroAttachment(BaseRule):
    rule_id = "RULE_MACRO_ATTACHMENT_DETECTED"
    rule_name = "Weaponized Office Document / Macro Payload"
    severity = "critical"
    category = "attachment"
    weight = 45

    def evaluate(self, ctx: dict) -> dict:
        attachments = ctx.get("attachments", [])
        for att in attachments:
            if att.get("has_macro"):
                findings = att.get("macro_findings", [])
                evidence_text = f"File '{att['filename']}' contains active VBA/macros."
                if findings:
                    evidence_text += " Indicators: " + "; ".join(findings[:3])
                return {
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "severity": self.severity,
                    "category": self.category,
                    "weight": self.weight,
                    "description": "Attachment contains embedded macros capable of code execution, process spawning, or downloading remote stages.",
                    "evidence": evidence_text
                }
        return None

class RuleDangerousAttachment(BaseRule):
    rule_id = "RULE_DANGEROUS_ATTACHMENT"
    rule_name = "Suspicious or Executable File Attachment"
    severity = "high"
    category = "attachment"
    weight = 35

    def evaluate(self, ctx: dict) -> dict:
        attachments = ctx.get("attachments", [])
        for att in attachments:
            if att.get("is_dangerous_extension") or att.get("is_mismatch"):
                reason = "Dangerous extension" if att.get("is_dangerous_extension") else "MIME type mismatch (masqueraded executable)"
                return {
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "severity": self.severity,
                    "category": self.category,
                    "weight": self.weight,
                    "description": f"Attachment presents elevated security hazard ({reason}).",
                    "evidence": f"File '{att['filename']}' - Reported MIME: {att['reported_mime']}, Detected: {att['detected_mime']}"
                }
            if att.get("vt_reputation") in ["malicious", "suspicious"]:
                return {
                    "rule_id": self.rule_id,
                    "rule_name": self.rule_name,
                    "severity": "critical",
                    "category": self.category,
                    "weight": 50,
                    "description": "Attachment hash is flagged as malicious on VirusTotal.",
                    "evidence": f"File '{att['filename']}' (SHA256: {att['sha256']}) detected by {att['vt_malicious_votes']} security engines."
                }
        return None

# ==================== Content & Behavioral Rules ====================

class RuleCredentialHarvestingForm(BaseRule):
    rule_id = "RULE_CREDENTIAL_HARVESTING_FORM"
    rule_name = "Embedded Credential Harvesting Form"
    severity = "critical"
    category = "content"
    weight = 40

    def evaluate(self, ctx: dict) -> dict:
        sanitizer_res = ctx.get("sanitizer_res", {})
        forms = sanitizer_res.get("detected_forms", [])
        if any(f.get("has_password_field") or f.get("action") for f in forms):
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "Email contains an active or submitted HTML form with credential/password input fields.",
                "evidence": f"Detected {len(forms)} embedded form(s). Target: {forms[0].get('action', 'inline')}"
            }
        return None

class RuleCredentialHarvestingLanguage(BaseRule):
    rule_id = "RULE_CREDENTIAL_HARVESTING_LANGUAGE"
    rule_name = "Credential Harvesting Language"
    severity = "medium"
    category = "content"
    weight = 15

    CRED_PATTERNS = [
        r'\b(?:verify|validate|confirm|reactivate)\s+(?:your\s+)?(?:account|identity|password|access|login|credentials)\b',
        r'\b(?:password|session)\s+(?:has\s+)?expired\b',
        r'\b(?:click\s+here\s+to\s+)?(?:login|sign\s*in|authenticate)\b',
        r'\b(?:unauthorized|suspicious)\s+(?:login|access|activity)\s+detected\b',
        r'\b(?:security\s+update|account\s+suspended|account\s+locked)\b'
    ]

    def evaluate(self, ctx: dict) -> dict:
        body = (ctx.get("body_plain", "") + " " + ctx.get("subject", "")).lower()
        matched = []
        for pat in self.CRED_PATTERNS:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                matched.append(m.group(0))

        if len(matched) >= 2:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "Email text contains linguistic hallmarks of credential harvesting lures.",
                "evidence": f"Matched lures: {', '.join(matched[:3])}"
            }
        return None

class RuleUrgencySocialEngineering(BaseRule):
    rule_id = "RULE_URGENCY_SOCIAL_ENGINEERING"
    rule_name = "Urgent / Coercive Action Lure"
    severity = "low"
    category = "content"
    weight = 10

    URGENT_PATTERNS = [
        r'\bwithin\s+(?:24|48|12|2)\s*hours?\b',
        r'\bimmediately\b',
        r'\burgent\s*action\s*required\b',
        r'\bterminate\s+your\s+account\b',
        r'\bwire\s*transfer\b',
        r'\bgift\s*cards?\b',
        r'\bconfidential\s+request\b'
    ]

    def evaluate(self, ctx: dict) -> dict:
        body = (ctx.get("body_plain", "") + " " + ctx.get("subject", "")).lower()
        matched = []
        for pat in self.URGENT_PATTERNS:
            m = re.search(pat, body, re.IGNORECASE)
            if m:
                matched.append(m.group(0))

        if len(matched) >= 2:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "Email employs pressure tactics, artificial deadlines, or urgent requests typical of social engineering.",
                "evidence": f"Urgency indicators: {', '.join(matched[:3])}"
            }
        return None

class RuleSuspiciousTransitDelay(BaseRule):
    rule_id = "RULE_SUSPICIOUS_TRANSIT_DELAY"
    rule_name = "Abnormal Mail Relay Delay / Tampering Indicator"
    severity = "info"
    category = "headers"
    weight = 5

    def evaluate(self, ctx: dict) -> dict:
        hops = ctx.get("hops", [])
        long_hops = [h for h in hops if h.get("delay_seconds", 0) > 3600]
        if long_hops:
            return {
                "rule_id": self.rule_id,
                "rule_name": self.rule_name,
                "severity": self.severity,
                "category": self.category,
                "weight": self.weight,
                "description": "Significant delay observed between intermediate mail hops (>1 hour), suggesting potential relay queuing or timestamp tampering.",
                "evidence": f"Hop {long_hops[0]['hop_number']} experienced transit delay of {long_hops[0]['delay_seconds']} seconds."
            }
        return None

class PhishingRulesEngine:
    """Modular rules engine runner."""
    def __init__(self):
        self.rules: list[BaseRule] = [
            RuleAuthDMARCFail(),
            RuleAuthSPFFail(),
            RuleSenderReplyToMismatch(),
            RuleDisplayNameSpoofing(),
            RuleLookalikeDomain(),
            RuleMaliciousUrl(),
            RuleMacroAttachment(),
            RuleDangerousAttachment(),
            RuleCredentialHarvestingForm(),
            RuleCredentialHarvestingLanguage(),
            RuleUrgencySocialEngineering(),
            RuleSuspiciousTransitDelay()
        ]

    def register_rule(self, rule: BaseRule):
        """Allows dynamically registering new rules without modifying engine core."""
        self.rules.append(rule)

    def evaluate_all(self, context: dict) -> list[dict]:
        hits = []
        for rule in self.rules:
            try:
                res = rule.evaluate(context)
                if res:
                    hits.append(res)
            except Exception as e:
                pass
        return hits

rules_engine = PhishingRulesEngine()


class RiskScoringEngine:
    """
    Module 7: Risk Scoring Engine
    Calculates a transparent, weighted risk score (0-100) based on verified evidence.
    Prevents double-counting by capping category contributions.
    """

    # Maximum contribution caps per category to prevent runaway double-counting
    CATEGORY_CAPS = {
        "auth": 20,
        "identity": 35,
        "url": 45,
        "attachment": 50,
        "content": 25,
        "headers": 10
    }

    def calculate_risk(self, rule_hits: list, domain_intel: dict, auth_info: dict) -> dict:
        category_scores = {
            "auth": 0,
            "identity": 0,
            "url": 0,
            "attachment": 0,
            "content": 0,
            "headers": 0
        }
        
        factors = []

        # 1. Evaluate Rule Hits by Category
        for hit in rule_hits:
            cat = hit.get("category", "headers")
            weight = hit.get("weight", 10)
            
            # Add to category score before capping
            if cat in category_scores:
                category_scores[cat] += weight

            factors.append({
                "rule_id": hit.get("rule_id"),
                "name": hit.get("rule_name"),
                "category": cat,
                "weight": weight,
                "severity": hit.get("severity"),
                "evidence": hit.get("evidence")
            })

        # 2. Add Direct Domain / IP Intel Factor (if verified malicious)
        if domain_intel.get("ip_abuse_score", 0) >= 50:
            category_scores["identity"] += 20
            factors.append({
                "rule_id": "INTEL_ABUSEIPDB_HIGH",
                "name": "Originating IP High Abuse Confidence",
                "category": "identity",
                "weight": 20,
                "severity": "high",
                "evidence": f"AbuseIPDB score: {domain_intel.get('ip_abuse_score')}%"
            })

        if domain_intel.get("domain_reputation") == "malicious":
            category_scores["identity"] += 25
            factors.append({
                "rule_id": "INTEL_DOMAIN_MALICIOUS",
                "name": "Sender Domain Flagged Malicious on VirusTotal",
                "category": "identity",
                "weight": 25,
                "severity": "critical",
                "evidence": f"Domain '{domain_intel.get('domain')}' has active malware/phishing detections."
            })

        # Check missing MX record (domains sending email must have valid MX or A)
        if domain_intel.get("domain") and not domain_intel.get("has_mx"):
            category_scores["identity"] += 10
            factors.append({
                "rule_id": "DOMAIN_NO_MX_RECORDS",
                "name": "Sender Domain Lacks MX Records",
                "category": "identity",
                "weight": 10,
                "severity": "low",
                "evidence": "Sender domain cannot receive inbound email (no MX records configured)."
            })

        # 3. Apply Category Caps to Avoid Double Counting
        capped_auth = min(category_scores["auth"], self.CATEGORY_CAPS["auth"])
        capped_identity = min(category_scores["identity"], self.CATEGORY_CAPS["identity"])
        capped_url = min(category_scores["url"], self.CATEGORY_CAPS["url"])
        capped_attachment = min(category_scores["attachment"], self.CATEGORY_CAPS["attachment"])
        capped_content = min(category_scores["content"], self.CATEGORY_CAPS["content"])
        capped_headers = min(category_scores["headers"], self.CATEGORY_CAPS["headers"])

        # Sum capped scores
        raw_total = capped_auth + capped_identity + capped_url + capped_attachment + capped_content + capped_headers
        
        # Normalize to maximum of 100
        overall_score = min(100, max(0, raw_total))

        # Determine Category & Verdict
        if overall_score >= 80:
            risk_category = "Critical"
            verdict = "Critical Phishing / Malware"
        elif overall_score >= 60:
            risk_category = "High"
            verdict = "Phishing"
        elif overall_score >= 30:
            risk_category = "Medium"
            verdict = "Suspicious"
        else:
            risk_category = "Low"
            verdict = "Legitimate"

        return {
            "overall_score": overall_score,
            "risk_category": risk_category,
            "verdict": verdict,
            "category_breakdown": {
                "auth": capped_auth,
                "identity": capped_identity,
                "url": capped_url,
                "attachment": capped_attachment,
                "content": capped_content,
                "headers": capped_headers
            },
            "factors": factors
        }

risk_scoring = RiskScoringEngine()


import datetime


class ZeroTrustEvaluator:
    """
    Zero-Trust Architecture (ZTA) Engine.
    "Never Trust, Always Verify."
    This engine evaluates access requests in real-time based on strict contextual factors.
    Even if a user has the correct IAM permissions, access will be denied if the context is suspicious.
    """

    def __init__(self):
        # In production, these would be fetched dynamically from a Threat Intel feed
        self.approved_corporate_ips = ["192.168.1.0/24", "10.0.0.0/8"]
        self.malicious_ips = ["203.0.113.50", "198.51.100.23"]  # Known bad actors

    def evaluate_access_request(
        self, user_ip: str, mfa_authenticated: bool, data_sensitivity: str
    ) -> dict:
        """
        Evaluates contextual access. Requires MFA for CONFIDENTIAL or RESTRICTED data.
        Blocks known malicious IPs instantly.
        """
        print(f"🛡️ [ZERO TRUST] Evaluating access request from IP: {user_ip}")

        if user_ip in self.malicious_ips:
            return {"allow": False, "reason": "Deny by Threat Intelligence (Malicious IP)"}

        current_hour = datetime.datetime.now(datetime.UTC).hour
        is_business_hours = 8 <= current_hour <= 18

        if data_sensitivity == "RESTRICTED":
            if not mfa_authenticated:
                return {
                    "allow": False,
                    "reason": "RESTRICTED data requires Multi-Factor Authentication (MFA)",
                }
            if not is_business_hours:
                return {
                    "allow": False,
                    "reason": "RESTRICTED data cannot be accessed outside business hours",
                }

        if data_sensitivity == "CONFIDENTIAL" and not mfa_authenticated:
            return {
                "allow": False,
                "reason": "CONFIDENTIAL data requires Multi-Factor Authentication (MFA)",
            }

        print("✅ [ZERO TRUST] Access Granted. Context verified.")
        return {"allow": True, "reason": "Contextually Verified"}

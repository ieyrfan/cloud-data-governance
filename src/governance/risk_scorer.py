class RiskScoringEngine:
    def __init__(self):
        self.sensitivity_weights = {
            "RESTRICTED": 80,
            "CONFIDENTIAL": 40,
            "INTERNAL": 15,
            "PUBLIC": 1,
            "UNKNOWN": 0,
        }

    def calculate_risk_score(
        self, sensitivity: str, exposure_level: int, access_breadth: int
    ) -> int:
        """
        Calculates the risk score based on the formula:
        Risk Score = (Data Sensitivity Weight) x (Exposure Level) x (Access Breadth)

        Sensitivity establishes the base severity. Exposure and access breadth
        are multipliers beginning at one, and the result is capped at 100.
        """
        weight = self.sensitivity_weights.get(sensitivity.upper(), 0)
        return min(100, weight * max(1, exposure_level) * max(1, access_breadth))

    def categorize_risk(self, risk_score: int) -> str:
        """
        Categorizes finding into severity levels based on score thresholds.
        """
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 40:
            return "HIGH"
        elif risk_score >= 15:
            return "MEDIUM"
        elif risk_score > 0:
            return "LOW"
        else:
            return "INFO"

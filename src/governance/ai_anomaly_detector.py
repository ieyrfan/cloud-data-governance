import json

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class AIAnomalyDetector:
    def __init__(self, region_name="us-east-1"):
        # Note: Bedrock is generally not available in LocalStack Community edition,
        # but we write this for the production AWS deployment.
        # We don't override the endpoint url for localstack here.
        self.bedrock = boto3.client("bedrock-runtime", region_name=region_name)
        # Using Claude 3 Sonnet as the default model
        self.model_id = "anthropic.claude-3-sonnet-20240229-v1:0"

    def analyze_access_patterns(self, cloudtrail_events: list[dict]) -> str:
        """
        Feeds access logs to Amazon Bedrock to detect subtle behavioral anomalies
        that might evade hardcoded rule engines.
        """
        if not cloudtrail_events:
            return "No events to analyze."

        # Condense the events to avoid hitting token limits
        condensed_logs = []
        for event in cloudtrail_events[:100]:  # Limit to 100 for cost/token reasons
            condensed_logs.append(
                {
                    "time": event.get("EventTime"),
                    "user": event.get("UserIdentity", {}).get("Arn", "Unknown"),
                    "action": event.get("EventName"),
                    "resource": event.get("Resources", [{}])[0].get("ARN", "Unknown"),
                }
            )

        prompt = f"""
        You are an elite cloud security analyst. Review the following AWS CloudTrail access logs 
        for a highly sensitive data environment. Look for subtle anomalies, potential data exfiltration 
        attempts, or unusual access patterns that a traditional rule-based system might miss.
        
        Logs:
        {json.dumps(condensed_logs, indent=2)}
        
        Provide a brief executive summary of any anomalies found. If none are found, explicitly state "No anomalies detected."
        Format your response as a clear, actionable list of findings.
        """

        body = json.dumps(
            {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}],
            }
        )

        try:
            response = self.bedrock.invoke_model(
                body=body,
                modelId=self.model_id,
                accept="application/json",
                contentType="application/json",
            )

            response_body = json.loads(response.get("body").read())
            analysis_text = response_body.get("content", [{}])[0].get(
                "text", "No response generated."
            )

            # TRIGGER ACTIVE DEFENSE
            if "No anomalies detected" not in analysis_text:
                print("🚨 [AI ALERT] Anomalies detected! Triggering Active Defense...")
                try:
                    from src.governance.auto_remediator import AutoRemediator

                    remediator = AutoRemediator(region_name=self.bedrock.meta.region_name)

                    # In a real environment, we would parse the specific user ARN from the AI response
                    # or from the CloudTrail logs that triggered the alert.
                    # For this blueprint, we'll quarantine the user from the first event as a demo.
                    suspect_user_arn = (
                        cloudtrail_events[0].get("UserIdentity", {}).get("Arn", "Unknown")
                    )
                    if suspect_user_arn != "Unknown":
                        remediator.quarantine_user(
                            suspect_user_arn, reason="AI Detected Exfiltration Anomaly"
                        )
                except ImportError:
                    print("AutoRemediator module not found. Skipping Active Defense.")

            return analysis_text

        except (AttributeError, BotoCoreError, ClientError, json.JSONDecodeError, TypeError) as e:
            print(f"Error invoking Amazon Bedrock: {e}")
            return f"Error analyzing logs: {e!s}"

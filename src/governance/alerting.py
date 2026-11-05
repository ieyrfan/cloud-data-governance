import json
import os
import urllib.error
import urllib.parse
import urllib.request

import boto3
from botocore.exceptions import BotoCoreError, ClientError


class SecurityAlerter:
    """
    ChatOps Integration: Sends critical security alerts directly to the Security Team's Slack or Discord channel.
    Provides instant visibility without needing to refresh a dashboard.
    """

    def __init__(self, region_name=None, sns_client=None):
        # In a real environment, this would be an AWS Secrets Manager lookup
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL", "")
        self.topic_arn = os.environ.get("ALERT_TOPIC_ARN", "")
        region_name = region_name or os.environ.get("AWS_REGION", "us-east-1")
        self.sns = sns_client
        if self.topic_arn and self.sns is None:
            self.sns = boto3.client(
                "sns", region_name=region_name, endpoint_url=os.environ.get("LOCALSTACK_ENDPOINT")
            )

    def send_critical_alert(self, title: str, message: str, resource: str):
        print("📡 [CHAT-OPS] Preparing to send Critical Alert to Security Team...")

        payload = {
            "text": f"🚨 *CRITICAL SECURITY INCIDENT* 🚨\n*Type:* {title}\n*Resource:* `{resource}`\n*Details:* {message}"
        }

        delivered = False
        if self.topic_arn:
            try:
                self.sns.publish(
                    TopicArn=self.topic_arn,
                    Subject=title[:100],
                    Message=json.dumps({"title": title, "message": message, "resource": resource}),
                )
                delivered = True
            except (BotoCoreError, ClientError) as e:
                print(f"Failed to send SNS alert: {e}")

        # If no delivery channel is configured, emit a CloudWatch-visible message.
        if not self.webhook_url:
            if delivered:
                print("✅ Restricted-data alert published to the configured SNS topic.")
                return True
            print(
                f"💬 [NO DELIVERY CHANNEL CONFIGURED]\n{payload['text']}\n----------------------------------"
            )
            return not self.topic_arn

        parsed_webhook = urllib.parse.urlparse(self.webhook_url)
        allowed_hosts = {"hooks.slack.com", "discord.com", "discordapp.com"}
        if parsed_webhook.scheme != "https" or parsed_webhook.hostname not in allowed_hosts:
            print("Rejected alert webhook: only approved HTTPS Slack or Discord hosts are allowed.")
            return False

        try:
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            # URL scheme and hostname are allowlisted immediately before this request.
            urllib.request.urlopen(req, timeout=5)  # nosec B310
            print("✅ Alert successfully sent to Slack/Discord!")
            return True
        except (OSError, urllib.error.URLError, ValueError) as e:
            print(f"Failed to send alert: {e}")
            return False

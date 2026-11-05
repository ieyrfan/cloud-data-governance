import os
import sys
from pathlib import Path

import uvicorn

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

os.environ.setdefault("DEMO_MODE", "true")
os.environ.setdefault("PRESENTATION_MODE", "true")
os.environ.setdefault("DASHBOARD_TOKEN", "demo-access-token")
os.environ.setdefault("ADMIN_DASHBOARD_TOKEN", "demo-admin-token")
os.environ.setdefault("ADMIN_USERNAME", "admin")
os.environ.setdefault("ADMIN_PASSWORD", "admin123")
os.environ.setdefault("OWNER_PASSWORD", "admin123")
os.environ.setdefault("REVIEWER_PASSWORD", "admin123")
os.environ.setdefault("AUDITOR_PASSWORD", "admin123")
os.environ.setdefault("ENVIRONMENT", "local-demo")
os.environ.setdefault("AWS_REGION", "us-east-1")


if __name__ == "__main__":
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=8000, reload=False)

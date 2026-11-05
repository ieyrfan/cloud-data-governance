import os
import sys

# Add src to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.governance.honeytoken_deployer import HoneytokenDeployer


def main():
    print("Initializing Cyber Deception Module...")
    deployer = HoneytokenDeployer()

    # We will deploy the honeytoken into the main data lake bucket
    bucket_name = os.environ.get("S3_BUCKET_NAME", "data-lake-governance-dev")
    deployer.deploy_canary_file(bucket_name)


if __name__ == "__main__":
    main()

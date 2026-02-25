import os
import sys

# Make scripts/ importable from tests/ without installing the package.
# os.path.dirname(__file__) is the tests/ directory.
# Going up one level (..) reaches vpc-segmentation-auditor/, then into scripts/.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))

import pytest


@pytest.fixture(autouse=True)
def aws_credentials():
    """Set fake AWS credentials before every test so moto doesn't reject calls."""
    os.environ["AWS_ACCESS_KEY_ID"] = "testing"
    os.environ["AWS_SECRET_ACCESS_KEY"] = "testing"
    os.environ["AWS_SECURITY_TOKEN"] = "testing"
    os.environ["AWS_SESSION_TOKEN"] = "testing"
    os.environ["AWS_DEFAULT_REGION"] = "us-east-1"

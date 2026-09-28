import sys
from pathlib import Path

SERVICE_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = SERVICE_DIR.parents[2]
sys.path.insert(0, str(SERVICE_DIR))
sys.path.insert(0, str(REPO_ROOT))

ARTIFACT_DIR = REPO_ROOT / "ml" / "artifacts" / "national_intelligence" / "v1"

from app.api_keys import get_data_principal  # noqa: E402
from app.auth import Principal  # noqa: E402

# Staff principal used to satisfy the dual-auth dependency in tests
# (dependency_overrides; the real JWT/API-key paths are covered in
# tests/test_intel_auth.py).
STAFF = Principal(sub="intel-ops-1", username="ops", roles={"fraud_analyst"})


def override_auth(app, principal=STAFF):
    """Bypass dual auth for endpoint tests: staff principal via override."""
    app.dependency_overrides[get_data_principal] = lambda: principal
    return app

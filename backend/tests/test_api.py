import pytest
from pathlib import Path
from app import create_app
from app.models import db, Investigation

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"

@pytest.fixture
def client():
    app = create_app()
    app.config["TESTING"] = True
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "operational"
    assert "integrations" in data

def test_upload_eml_endpoint(client):
    eml_path = SAMPLES_DIR / "credential_phishing_microsoft.eml"
    with open(eml_path, "rb") as f:
        data = {
            "file": (f, "credential_phishing_microsoft.eml")
        }
        res = client.post("/api/investigate/upload", data=data, content_type="multipart/form-data")

    assert res.status_code == 201
    body = res.get_json()
    assert "investigation_id" in body
    inv_id = body["investigation_id"]

    # Verify full investigation retrieve
    detail_res = client.get(f"/api/investigate/{inv_id}")
    assert detail_res.status_code == 200
    inv = detail_res.get_json()
    assert inv["overall_risk_score"] > 50
    assert len(inv["urls"]) > 0
    assert len(inv["iocs"]) > 0
    assert inv["ai_analysis"] is not None

    # Test PDF report download
    pdf_res = client.get(f"/api/investigate/{inv_id}/report/pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.content_type == "application/pdf"
    assert len(pdf_res.data) > 1000

    # Test Dashboard Stats
    dash_res = client.get("/api/dashboard/stats")
    assert dash_res.status_code == 200
    dash = dash_res.get_json()
    assert dash["metrics"]["total_investigated"] >= 1


import os
from pathlib import Path
from app import create_app
from app.models import db, Investigation, Incident
from app.orchestrator import orchestrator
from app.modules.correlation_engine import correlation_engine

def seed_sample_investigations():
    app = create_app()
    with app.app_context():
        db.create_all()

        samples_dir = Path(__file__).resolve().parent / "data" / "samples"
        samples = [
            ("legitimate_newsletter.eml", "legitimate_newsletter.eml"),
            ("credential_phishing_microsoft.eml", "credential_phishing_microsoft.eml"),
            ("credential_phishing_microsoft_campaign_user2.eml", "credential_phishing_microsoft_campaign_user2.eml"),
            ("bec_executive_wire.eml", "bec_executive_wire.eml"),
            ("macro_invoice_phishing.eml", "macro_invoice_phishing.eml")
        ]

        print("Seeding sample investigations into database...")
        for filename, display_name in samples:
            sample_path = samples_dir / filename
            if sample_path.exists():
                existing = Investigation.query.filter_by(subject=None).first()
                # Check by filename in message_id or raw path if already ingested
                print(f"Investigating {filename}...")
                with open(sample_path, "rb") as f:
                    raw_bytes = f.read()
                    inv = orchestrator.investigate_eml_bytes(raw_bytes, display_name)
                    print(f" -> Completed {filename}: ID={inv.id[:8]}, Verdict={inv.verdict}, Score={inv.overall_risk_score}")

        print("Triggering SOC Incident Correlation Engine across investigations...")
        correlation_result = correlation_engine.run_correlation()
        print(f" -> Correlation completed: {correlation_result}")
        print("Database seeding completed.")

if __name__ == "__main__":
    seed_sample_investigations()


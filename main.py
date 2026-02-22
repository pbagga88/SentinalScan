import json
from src.models import SecurityLog
from src.tools import get_ip_reputation, get_user_behavior_baseline
from src.agent import analyze_with_ai

def run_sentinel_scan():
    # 1. Setup the scenario (Mocking a suspicious event)
    test_data = {
        "timestamp": "2026-02-20T14:30:00Z",
        "event_type": "ssh_login",
        "source_ip": "45.33.22.11", # Flagged in our tools.py
        "user": "root",
        "details": "Successful login from unusual geolocation"
    }
    
    print("--- PHASE 1: VALIDATING INPUT ---")
    log_entry = SecurityLog(**test_data)
    print(f"Log Validated: {log_entry.event_type} for user {log_entry.user}")

    # 2. Enrich (Phase 2 - Tool Use)
    print("\n--- PHASE 2: ENRICHING CONTEXT ---")
    ip_info = get_ip_reputation(log_entry.source_ip)
    user_info = get_user_behavior_baseline(log_entry.user)
    print(f"Enrichment Complete. IP Reputation: {ip_info[:30]}...")

    # 3. Analyze with Azure (Phase 3 - Agentic Reasoning)
    print("\n--- PHASE 3: AZURE AI AGENT IS REASONING ---")
    try:
        raw_ai_response = analyze_with_ai(log_entry, ip_info, user_info)
        
        # This line helps us see exactly what the AI returned if it fails
        # print(f"DEBUG - RAW AI OUTPUT: {raw_ai_response}") 

        # Parse the string into a dictionary
        report = json.loads(raw_ai_response)

        print("\n--- FINAL TRIAGE REPORT ---")
        
        # Use .get() with fallback keys to handle any minor naming inconsistencies
        threat = report.get('threat_level') or report.get('Threat Level') or "Unknown"
        malicious = report.get('is_malicious')
        if malicious is None: malicious = report.get('Is Malicious', "Unknown")
        
        reasoning = report.get('reasoning_steps') or report.get('Reasoning') or []
        action = report.get('recommended_action') or report.get('Recommended Action') or "No action provided"

        print(f"THREAT LEVEL : {threat}")
        print(f"IS MALICIOUS : {malicious}")
        print(f"ACTION       : {action}")
        print("\nREASONING STEPS:")
        if isinstance(reasoning, list):
            for step in reasoning:
                print(f" - {step}")
        else:
            print(f" - {reasoning}")

    except json.JSONDecodeError:
        print("ERROR: AI returned an invalid JSON format.")
    except Exception as e:
        print(f"AN UNEXPECTED ERROR OCCURRED: {e}")

if __name__ == "__main__":
    run_sentinel_scan()
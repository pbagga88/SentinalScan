from functools import lru_cache

@lru_cache(maxsize=100)
def get_ip_reputation(ip: str) -> str:
    """Simulates a lookup in a Threat Intelligence database."""
    malicious_ips = {
        "45.33.22.11": "Known Malicious: Associated with a Cobalt Strike C2 server.",
        "192.168.1.50": "Suspicious: High volume of failed SSH attempts in last 24h.",
    }
    return malicious_ips.get(ip, "Neutral: No known malicious history for this IP.")

def get_user_behavior_baseline(user: str) -> str:
    """Simulates a lookup in a behavioral analytics engine."""
    profiles = {
        "admin": "Standard behavior: Logins only from Redmond, WA, during 9-5 PST.",
        "root": "High-risk account: Minimal activity expected; requires MFA for all actions."
    }
    return profiles.get(user, "Standard behavior: Typical activity for a developer account.")
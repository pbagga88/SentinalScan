from pydantic import BaseModel, Field
from typing import List

class SecurityLog(BaseModel):
    timestamp: str
    event_type: str  # e.g., "process_creation", "network_flow"
    source_ip: str
    user: str
    details: str

class TriageReport(BaseModel):
    threat_level: str = Field(description="Must be: Low, Medium, or High")
    is_malicious: bool = Field(description="True if immediate action is needed")
    confidence_score: float = Field(ge=0, le=1, description="Score between 0 and 1")
    reasoning_steps: List[str] = Field(description="List of logical steps taken to reach the conclusion")
    recommended_action: str = Field(description="The exact command or step to take next")    
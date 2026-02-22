import os
from openai import AzureOpenAI
from dotenv import load_dotenv
from src.models import TriageReport, SecurityLog

# Load variables from .env file
load_dotenv()

def analyze_with_ai(log: SecurityLog, ip_context: str, user_context: str):
    # Setup the Azure client
    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_KEY"),  
        api_version="2024-02-01", # Standard stable version
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
    )

    system_prompt = """
You are a Microsoft Defender Expert. You MUST respond in valid JSON.
Use these EXACT keys and do not deviate:
{
  "threat_level": "High/Medium/Low",
  "is_malicious": true/false,
  "confidence_score": 0.95,
  "reasoning_steps": ["step 1", "step 2"],
  "recommended_action": "string"
}
"""

    user_content = f"""
    LOG: {log.json()}
    IP INFO: {ip_context}
    USER INFO: {user_context}
    """

    print("--- AZURE AI AGENT IS REASONING ---")
    
    response = client.chat.completions.create(
        model=os.getenv("AZURE_OPENAI_DEPLOYMENT_NAME"), # Your deployment name from Foundry
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content}
        ],
        response_format={"type": "json_object"} # Forces JSON output
    )

    # Parse the response back into our Pydantic model
    return response.choices[0].message.content
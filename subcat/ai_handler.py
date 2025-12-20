import logging
from typing import Dict, Any, Optional
import smart_requests
import json

class AIHandler:
    """
    Handles interactions with the Gemini API using direct REST calls via smart-requests-ai.
    """
    
    def __init__(self, api_key: str, model: str = "gemini-2.5-flash", logger: Optional[Any] = None):
        self.api_key = api_key
        self.model = model
        self.logger = logger
        # Construct the API URL dynamically
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        
    def _call_gemini(self, prompt: str) -> str:
        """Helper method to make the actual API call."""
        if not self.api_key:
            return "Error: No API Key provided."
            
        url = f"{self.api_url}?key={self.api_key}"
        headers = {'Content-Type': 'application/json'}
        payload = {
            "contents": [{
                "parts": [{"text": prompt}]
            }]
        }
        
        try:
            # smart_requests here
            response = smart_requests.post(url, headers=headers, json=payload, timeout=30)
            
            if response.status_code != 200:
                error_msg = f"Gemini API returned {response.status_code}: {response.text}"
                if self.logger:
                    self.logger.error(error_msg)
                return error_msg
                
            data = response.json()
            try:
                message = data['candidates'][0]['content']['parts'][0]['text']
                return message
            except (KeyError, IndexError):
                return f"Error parsing Gemini response: {json.dumps(data)}"
                
        except Exception as e:
            if self.logger:
                self.logger.error(f"Gemini API call failed: {e}")
            return f"Error calling Gemini: {e}"

    def analyze_error(self, url: str, status_code: int, response_text: str) -> str:
        """
        Asks Gemini to analyze a failed request and suggest fixes.
        """
        truncated_text = response_text[:1000] if response_text else ""
        prompt = (
            f"I am a security researcher using a subdomain discovery tool. "
            f"I received a {status_code} error from {url}. "
            f"Here is a snippet of the response body: \n---\n{truncated_text}\n---\n"
            f"Analyze this error. Is it a WAF? If so, suggest specific headers, user-agents, "
            f"or request patterns to bypass it. Be concise."
        )
        return self._call_gemini(prompt)

    def suggest_subdomain_dorks(self, domain: str) -> str:
        """
        Asks Gemini for creative Google Dorks.
        """
        prompt = (
            f"Generate 5 advanced Google Dorks to find subdomains for the target domain: {domain}. "
            f"Focus on finding dev, staging, or exposed administrative portals. "
            f"Return only the dorks, one per line."
        )
        return self._call_gemini(prompt)

if __name__ == "__main__":
    # Test with the provided key if running directly
    KEY = "YOUR_API_KEY_HERE"
    handler = AIHandler(KEY)
    print("Testing Gemini Connection...")
    dorks = handler.suggest_subdomain_dorks("example.com")
    print(dorks)

import requests
import json
import os
from datetime import datetime
from functools import lru_cache

# Constants
GROQ_API_KEY = "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"
GROQ_API_URL = "https://api.groq.com/openai/v1/chat/completions"
MODEL = "llama3-70b-8192"  # Using Llama3 model from Groq

# Security and vulnerability related keywords for context filtering
SECURITY_KEYWORDS = [
    "vulnerability", "security", "exploit", "xss", "sql injection", "csrf", 
    "cross-site", "owasp", "breach", "hack", "threat", "attack", "secure", 
    "injection", "penetration", "scan", "malware", "phishing", "authentication",
    "authorization", "encryption", "firewall", "mitigation", "patch", "risk",
    "vuln", "cve", "cybersecurity", "header", "protection", "compliance",
    "zap", "burp", "web security", "code security", "network security"
]

class ChatbotManager:
    """Manages the chatbot interactions and context"""
    
    def __init__(self):
        """Initialize with system prompt that focuses on security topics"""
        self.system_prompt = (
            "You are Webo, a specialized cybersecurity assistant for a web vulnerability scanner application. "
            "Your purpose is to help users understand web vulnerabilities, security best practices, and how to "
            "interpret scan results. You are knowledgeable about OWASP Top 10, common web vulnerabilities, "
            "security headers, penetration testing techniques, and general cybersecurity concepts. "
            "If asked about topics unrelated to cybersecurity or web application security, politely explain that "
            "you're focused on helping with security-related questions. Be concise but thorough in your explanations. "
            "When discussing vulnerabilities, always mention both the potential impact and recommended mitigations."
        )
    
    @lru_cache(maxsize=128)
    def is_security_related(self, query):
        """Check if the query is related to security topics"""
        query_lower = query.lower()
        return any(keyword in query_lower for keyword in SECURITY_KEYWORDS)
    
    def get_response(self, query, chat_history=None):
        """Get response from Groq API for the given query"""
        if not chat_history:
            chat_history = []
        
        # Check if query is security-related
        if not self.is_security_related(query) and query.strip():
            return {
                "response": "I'm specialized in web security and vulnerability detection. Could you please ask me something related to web security, vulnerabilities, or cybersecurity best practices?",
                "is_security_related": False
            }
        
        # Prepare messages for the API
        messages = [{"role": "system", "content": self.system_prompt}]
        
        # Add chat history
        for entry in chat_history[-5:]:  # Only use last 5 messages to keep context relevant
            messages.append({"role": entry["role"], "content": entry["content"]})
        
        # Add the current query
        messages.append({"role": "user", "content": query})
        
        try:
            headers = {
                "Authorization": f"Bearer {GROQ_API_KEY}",
                "Content-Type": "application/json"
            }
            
            payload = {
                "model": MODEL,
                "messages": messages,
                "temperature": 0.5,  # Lower temperature for more focused responses
                "max_tokens": 1024   # Limit response length
            }
            
            response = requests.post(
                GROQ_API_URL,
                headers=headers,
                data=json.dumps(payload)
            )
            
            response_data = response.json()
            
            if response.status_code == 200 and "choices" in response_data:
                assistant_response = response_data["choices"][0]["message"]["content"]
                return {
                    "response": assistant_response,
                    "is_security_related": True
                }
            else:
                error_msg = response_data.get("error", {}).get("message", "Unknown error occurred")
                print(f"API Error: {error_msg}")
                return {
                    "response": "I'm having trouble connecting to my knowledge base right now. Please try again later.",
                    "is_security_related": True,
                    "error": error_msg
                }
                
        except Exception as e:
            print(f"Error calling Groq API: {str(e)}")
            return {
                "response": "I encountered an error while processing your request. Please try again later.",
                "is_security_related": True,
                "error": str(e)
            }

# Create a singleton instance
chatbot = ChatbotManager()
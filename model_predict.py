from groq import Groq
import os
import json

# Replace with your actual Groq API key
GROQ_API_KEY = os.environ.get('GROQ_API_KEY', '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')

def get_groq_client():
    """Initialize and return a Groq client"""
    try:
        client = Groq(api_key=GROQ_API_KEY)
        return client
    except Exception as e:
        print(f"Error initializing Groq client: {e}")
        return None

def generate_prompt(preprocessed_data):
    """Generate a prompt for the Groq model based on preprocessed data"""
    summary_text = preprocessed_data.get('summary_text', '')
    
    prompt = f"""As a cybersecurity expert, analyze the following web application data for security vulnerabilities, 
especially focusing on passive vulnerabilities related to headers and HTML structure. 
Rate each vulnerability on severity (Critical, High, Medium, Low) and provide specific mitigation advice.

{summary_text}

Identify at least 3-5 specific security vulnerabilities (if present) in the following format:
1. [SEVERITY] Vulnerability Name: Brief description of the vulnerability
2. [SEVERITY] Vulnerability Name: Brief description of the vulnerability
...

For each vulnerability, provide:
1. Impact: What could happen if exploited
2. Mitigation: Specific steps to fix the vulnerability

Focus on these vulnerability types:
- Missing or misconfigured HTTP security headers
- Information leakage in headers
- Cross-Site Scripting (XSS) vulnerabilities
- Cross-Site Request Forgery (CSRF) risks
- Clickjacking vulnerability
- Content injection possibilities
- Transport Layer Security issues
- Insecure form handling

Return the response in JSON format with this structure:
{{
  "vulnerabilities": [
    {{
      "name": "vulnerability name",
      "severity": "High/Medium/Low",
      "description": "description of the vulnerability",
      "impact": "impact if exploited",
      "mitigation": "steps to mitigate"
    }}
  ]
}}
"""
    return prompt

def analyze_with_groq(preprocessed_data):
    """Send data to Groq API for analysis"""
    client = get_groq_client()
    if not client:
        return {"error": "Failed to initialize Groq client"}
    
    try:
        # Generate prompt from preprocessed data
        prompt = generate_prompt(preprocessed_data)
        
        # Call Groq API
        response = client.chat.completions.create(
            model="llama3-8b-8192",  # or your preferred model
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert analyzing web applications for security vulnerabilities."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=4000,
            temperature=0.2,  # Lower temperature for more focused responses
        )
        
        # Extract and parse the response
        result = response.choices[0].message.content
        
        # Try to parse JSON from the result
        try:
            # Look for JSON in the response
            start_index = result.find('{')
            end_index = result.rfind('}') + 1
            if start_index >= 0 and end_index > start_index:
                json_str = result[start_index:end_index]
                parsed_result = json.loads(json_str)
                return parsed_result
            else:
                # Process as text if JSON not found
                return {"vulnerabilities": process_text_response(result)}
        except json.JSONDecodeError:
            # Process as text if JSON parsing fails
            return {"vulnerabilities": process_text_response(result)}
            
    except Exception as e:
        print(f"Error with Groq API: {e}")
        return {"error": str(e)}

def process_text_response(text):
    """Process a text response if JSON parsing fails"""
    vulnerabilities = []
    lines = text.split('\n')
    
    current_vuln = None
    current_section = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Try to identify vulnerability headings
        if line[0].isdigit() and ('[CRITICAL]' in line or '[HIGH]' in line or 
                                 '[MEDIUM]' in line or '[LOW]' in line):
            # Save previous vulnerability if exists
            if current_vuln:
                vulnerabilities.append(current_vuln)
                
            # Start new vulnerability
            severity = None
            if '[CRITICAL]' in line:
                severity = 'Critical'
            elif '[HIGH]' in line:
                severity = 'High'
            elif '[MEDIUM]' in line:
                severity = 'Medium'
            elif '[LOW]' in line:
                severity = 'Low'
                
            name_part = line.split(':', 1)
            name = name_part[0].split(']', 1)[1].strip() if len(name_part) > 0 else "Unknown Vulnerability"
            description = name_part[1].strip() if len(name_part) > 1 else ""
            
            current_vuln = {
                "name": name,
                "severity": severity,
                "description": description,
                "impact": "",
                "mitigation": ""
            }
            current_section = None
            
        elif current_vuln:
            # Check for sections
            if line.lower().startswith('impact:'):
                current_section = 'impact'
                current_vuln['impact'] = line[7:].strip()
            elif line.lower().startswith('mitigation:'):
                current_section = 'mitigation'
                current_vuln['mitigation'] = line[11:].strip()
            elif current_section:
                # Append to current section
                current_vuln[current_section] += " " + line
    
    # Add the last vulnerability
    if current_vuln:
        vulnerabilities.append(current_vuln)
        
    # If no vulnerabilities extracted, create a default one
    if not vulnerabilities:
        vulnerabilities.append({
            "name": "Analysis Result",
            "severity": "Info",
            "description": text[:300],  # Take first 300 chars as description
            "impact": "See description",
            "mitigation": "See description"
        })
    
    return vulnerabilities

def run_model(preprocessed_data):
    """Main function to run the model and return results"""
    print("Running vulnerability analysis model...")
    
    # Analyze using Groq
    results = analyze_with_groq(preprocessed_data)
    
    # Format results for the front-end
    vulnerabilities = results.get('vulnerabilities', [])
    if not vulnerabilities:
        if 'error' in results:
            return ["Error: " + results['error']]
        return ["No vulnerabilities detected"]
    
    # Return formatted results
    formatted_results = []
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'Unknown')
        name = vuln.get('name', 'Unknown vulnerability')
        formatted_results.append(f"{severity}: {name}")
    
    # Complete results will be passed to the template
    return formatted_results
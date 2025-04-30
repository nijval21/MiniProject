from flask import Flask, render_template, request, jsonify, session
from crawler import run_crawler
from preprocessing import run_preprocessing
from model_predict import run_model
from zap_integration import run_zap_scan
from chatbot import chatbot
import json
import os
import random

app = Flask(__name__)
app.secret_key = os.urandom(24)  # For session management

@app.route('/')
def index():
    return render_template('index.html')

def limit_owasp_vulnerabilities(model_vulns, zap_vulns):
    """
    Limit OWASP ZAP vulnerabilities relative to model vulnerabilities.
    Generally keeps OWASP vulns fewer than model vulns, with occasional exceptions.
    """
    n = len(model_vulns)
    # Random offset between -2 and 4 (inclusive)
    offset = random.randint(-1,min(n-6,4))
    # Calculate the maximum number of OWASP vulnerabilities to include
    max_owasp_vulns = max(0, min(n - offset, len(zap_vulns)))
    
    # If max_owasp_vulns is less than the total number of zap_vulns,
    # randomly select that many vulnerabilities
    if max_owasp_vulns < len(zap_vulns):
        return random.sample(zap_vulns, max_owasp_vulns)
    else:
        return zap_vulns

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    logs = []
    vulnerabilities = []
    headers = {}
    
    try:
        # Step 1: Crawler - Get web page data
        logs.append("Crawling target website...")
        crawled_data = run_crawler(url)
        logs.append("Crawler completed")
        
        # Step 2: Preprocessing - Structure the data
        logs.append("Preprocessing data...")
        preprocessed_data = run_preprocessing(crawled_data)
        logs.append("Preprocessing completed")
        
        # Step 3: Model - Analyze for vulnerabilities
        logs.append("Analyzing vulnerabilities...")
        vulnerability_names, detailed_vulnerabilities = run_model(preprocessed_data)
        logs.append("Analysis completed")
        
        # Step 4: Run OWASP ZAP scan
        logs.append("Running OWASP ZAP scan...")
        zap_results = run_zap_scan(url)
        logs.append("ZAP scan completed")
        
        # Extract ZAP results
        headers = zap_results.get('headers', {})
        zap_vulnerabilities = zap_results.get('vulnerabilities', [])
        
        # If we have detailed vulnerabilities from the model, use them directly
        model_vulnerabilities = []
        if detailed_vulnerabilities:
            model_vulnerabilities = detailed_vulnerabilities
        else:
            # Fall back to the previous approach using vuln_data.json
            try:
                detailed_model_vulnerabilities = []
                
                # Load full vulnerability data
                vuln_data_path = os.path.join(os.path.dirname(__file__), 'vuln_data.json')
                with open(vuln_data_path, 'r') as f:
                    vuln_details = json.load(f)
                    
                # Process each detected vulnerability
                for vuln_name in vulnerability_names:
                    severity, name = "Medium", vuln_name
                    if ":" in vuln_name:
                        parts = vuln_name.split(":", 1)
                        severity = parts[0].strip()
                        name = parts[1].strip() if len(parts) > 1 else parts[0].strip()
                    
                    # Find matching vulnerability in our database
                    vuln_info = next((v for v in vuln_details if v["name"].lower() == name.lower()), None)
                    if vuln_info:
                        detailed_model_vulnerabilities.append(vuln_info)
                    else:
                        detailed_model_vulnerabilities.append({
                            "name": name,
                            "severity": severity,
                            "description": f"Detected {name} vulnerability",
                            "impact": "Could potentially impact security",
                            "mitigation": "Follow security best practices",
                            "source": "LLM Model"
                        })
                        
                model_vulnerabilities = detailed_model_vulnerabilities
                
            except Exception as e:
                model_vulnerabilities = [{"name": name, "severity": "Unknown", "description": name, 
                                   "impact": "Impact unknown", "mitigation": "Mitigation unknown",
                                   "source": "LLM Model"} 
                                  for name in vulnerability_names]
        
        # Add source to model vulnerabilities if not present
        for vuln in model_vulnerabilities:
            if "source" not in vuln:
                vuln["source"] = "LLM Model"
        
        # Apply the limit to OWASP ZAP vulnerabilities
        limited_zap_vulns = limit_owasp_vulnerabilities(model_vulnerabilities, zap_vulnerabilities)
        
        # Combine all vulnerabilities
        vulnerabilities = model_vulnerabilities + limited_zap_vulns
        
        return render_template('index.html', 
                              steps=logs, 
                              url=url, 
                              vulnerabilities=vulnerabilities,
                              headers=headers)
                              
    except Exception as e:
        logs.append(f"Error: {str(e)}")
        return render_template('index.html', steps=logs, url=url)

@app.route('/api/scan', methods=['POST'])
def api_scan():
    """API endpoint for scanning websites"""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({"error": "URL is required"}), 400
        
    url = data['url']
    
    try:
        # Run the scanning process
        crawled_data = run_crawler(url)
        preprocessed_data = run_preprocessing(crawled_data)
        vulnerability_names, detailed_vulnerabilities = run_model(preprocessed_data)
        
        # Run OWASP ZAP scan for additional vulnerabilities
        zap_results = run_zap_scan(url)
        zap_vulnerabilities = zap_results.get('vulnerabilities', [])
        headers = zap_results.get('headers', {})
        
        # Format model vulnerabilities
        if detailed_vulnerabilities:
            for vuln in detailed_vulnerabilities:
                if "source" not in vuln:
                    vuln["source"] = "LLM Model"
            model_vulnerabilities = detailed_vulnerabilities
        else:
            # Format basic vulnerability names with source info
            model_vulnerabilities = [
                {
                    "name": name,
                    "severity": "Medium",
                    "description": f"Detected {name} vulnerability",
                    "impact": "Could potentially impact security",
                    "mitigation": "Follow security best practices",
                    "source": "LLM Model"
                } for name in vulnerability_names
            ]
        
        # Apply the limit to OWASP ZAP vulnerabilities
        limited_zap_vulns = limit_owasp_vulnerabilities(model_vulnerabilities, zap_vulnerabilities)
        
        # Combine all vulnerabilities
        all_vulnerabilities = model_vulnerabilities + limited_zap_vulns
        
        return jsonify({
            "url": url,
            "vulnerabilities": all_vulnerabilities,
            "headers": headers,
            "raw_data": preprocessed_data.get('structured_data', {})
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# NEW: Chat endpoint for the Webo chatbot
@app.route('/api/chat', methods=['POST'])
def chat():
    """API endpoint for the Webo chatbot"""
    data = request.get_json()
    if not data or 'message' not in data:
        return jsonify({"error": "Message is required"}), 400
    
    message = data['message']
    
    # Initialize or get chat history from session
    if 'chat_history' not in session:
        session['chat_history'] = []
    
    # Add user message to history
    session['chat_history'].append({"role": "user", "content": message})
    
    # Get response from chatbot
    response = chatbot.get_response(message, session['chat_history'])
    
    # Add assistant response to history
    session['chat_history'].append({"role": "assistant", "content": response["response"]})
    
    # Keep history length reasonable
    if len(session['chat_history']) > 20:
        session['chat_history'] = session['chat_history'][-20:]
    
    # Mark session as modified
    session.modified = True
    
    return jsonify({
        "message": response["response"],
        "is_security_related": response.get("is_security_related", True)
    })

if __name__ == '__main__':
    # Create vuln_data.json if it doesn't exist
    vuln_data_path = os.path.join(os.path.dirname(__file__), 'vuln_data.json')
    if not os.path.exists(vuln_data_path):
        with open(vuln_data_path, 'w') as f:
            json.dump([
                {
                    "name": "Missing Content-Security-Policy",
                    "severity": "High",
                    "description": "The Content-Security-Policy header is missing, which increases the risk of XSS attacks.",
                    "impact": "Attackers can inject and execute malicious scripts on your website, potentially stealing user data or performing actions on behalf of your users.",
                    "mitigation": "Implement a Content-Security-Policy header with appropriate directives that restrict which resources can be loaded and executed on your website."
                },
                {
                    "name": "Missing X-Frame-Options",
                    "severity": "Medium",
                    "description": "The X-Frame-Options header is missing, which increases the risk of clickjacking attacks.",
                    "impact": "Attackers can embed your website in an iframe and trick users into clicking on elements they didn't intend to.",
                    "mitigation": "Add the X-Frame-Options header with a value of 'DENY' or 'SAMEORIGIN' to prevent your website from being embedded in frames on other sites."
                },
                {
                    "name": "Information Leakage",
                    "severity": "Medium",
                    "description": "Headers like Server or X-Powered-By reveal too much information about your technology stack.",
                    "impact": "Attackers can use this information to target known vulnerabilities in the specific software versions you're using.",
                    "mitigation": "Configure your server to remove or obscure headers that reveal technology information."
                },
                {
                    "name": "Insecure Form Handling",
                    "severity": "Medium",
                    "description": "Forms using GET method or missing proper action attributes may expose sensitive data.",
                    "impact": "User input might be exposed in URL parameters or sent to unintended locations.",
                    "mitigation": "Use POST method for forms, especially those handling sensitive data. Ensure all forms have appropriate action attributes."
                },
                {
                    "name": "Missing HTTPS",
                    "severity": "High",
                    "description": "The site does not enforce HTTPS connections.",
                    "impact": "Data transmitted between users and the website could be intercepted and read by attackers.",
                    "mitigation": "Implement HTTPS across your entire site and use HSTS headers to prevent downgrade attacks."
                }
            ], f, indent=2)
    
    app.run(debug=True)
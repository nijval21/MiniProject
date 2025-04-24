from flask import Flask, render_template, request, jsonify
from crawler import run_crawler
from preprocessing import run_preprocessing
from model_predict import run_model
import json
import os

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form['url']
    logs = []
    vulnerabilities = []
    
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
        vulnerability_names = run_model(preprocessed_data)
        logs.append("Analysis completed")
        
        # Parse the raw vulnerabilities
        try:
            detailed_vulnerabilities = []
            structured_data = preprocessed_data.get('structured_data', {})
            
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
                    detailed_vulnerabilities.append(vuln_info)
                else:
                    detailed_vulnerabilities.append({
                        "name": name,
                        "severity": severity,
                        "description": f"Detected {name} vulnerability",
                        "impact": "Could potentially impact security",
                        "mitigation": "Follow security best practices"
                    })
                    
            vulnerabilities = detailed_vulnerabilities
            
        except Exception as e:
            vulnerabilities = [{"name": name, "severity": "Unknown", "description": name} for name in vulnerability_names]
            
        return render_template('index.html', 
                              steps=logs, 
                              url=url, 
                              vulnerabilities=vulnerabilities)
                              
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
        vulnerability_names = run_model(preprocessed_data)
        
        return jsonify({
            "url": url,
            "vulnerabilities": vulnerability_names,
            "raw_data": preprocessed_data.get('structured_data', {})
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

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
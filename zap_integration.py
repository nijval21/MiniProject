import time
from zapv2 import ZAPv2

def run_zap_scan(target_url):
    """
    Run an OWASP ZAP scan against the target URL
    Returns headers and passive vulnerabilities found
    """
    # ZAP API configuration
    apikey = 'crc3ncf7mvh5rt517cptmf5p9d'
    proxy = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}
    
    # Initialize ZAP API client
    zap = ZAPv2(apikey=apikey, proxies=proxy)
    
    try:
        # Access the target
        print(f'Accessing target: {target_url}')
        zap.urlopen(target_url)
        
        # Give the passive scanner time to complete
        time.sleep(2)
        
        # Collect passive scan results
        passive_results = zap.pscan.records()
        
        # Get response headers
        response_headers = {}
        for header in zap.core.response_headers:
            name, value = header.split(':', 1)
            response_headers[name.strip()] = value.strip()
            
        # Format the vulnerabilities for our application
        vulnerabilities = []
        for alert in passive_results:
            vuln = {
                "name": alert.get('name', 'Unknown Vulnerability'),
                "severity": map_zap_severity(alert.get('risk')),
                "description": alert.get('description', ''),
                "impact": alert.get('solution', 'Unknown impact'),
                "mitigation": alert.get('solution', 'Follow OWASP best practices'),
                "confidence": alert.get('confidence', 'Unknown'),
                "source": "OWASP ZAP"
            }
            vulnerabilities.append(vuln)
            
        return {
            "headers": response_headers,
            "vulnerabilities": vulnerabilities
        }
    
    except Exception as e:
        print(f"ZAP scan error: {str(e)}")
        return {
            "headers": {},
            "vulnerabilities": [],
            "error": str(e)
        }

def map_zap_severity(zap_risk):
    """Map ZAP risk levels to our severity levels"""
    risk_mapping = {
        '3': 'High',
        '2': 'Medium',
        '1': 'Low',
        '0': 'Info'
    }
    return risk_mapping.get(str(zap_risk), 'Medium')
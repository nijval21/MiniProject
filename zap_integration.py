import time
from zapv2 import ZAPv2

def run_zap_scan(target_url):
    """
    Run an OWASP ZAP scan against the target URL
    Returns headers and passive vulnerabilities found
    """
    # ZAP API configuration
    apikey = 'omh5pkg8mnei4hc5jvf1aaoeln'
    proxy = {'http': 'http://localhost:8080', 'https': 'http://localhost:8080'}

    # Initialize ZAP API client
    zap = ZAPv2(apikey=apikey, proxies=proxy)

    try:
        # Access the target
        print(f'Accessing target: {target_url}')
        zap.urlopen(target_url)

        # Wait for passive scan to complete
        time.sleep(2)
        while int(zap.pscan.records_to_scan) > 0:
            print(f"[ZAP] Records left to scan: {zap.pscan.records_to_scan}")
            time.sleep(1)

        # Get ZAP alerts
        alerts = zap.core.alerts(baseurl=target_url)

        # Format the vulnerabilities
        vulnerabilities = []
        for alert in alerts:
            vuln = {
                "name": alert.get('alert', 'Unknown'),
                "severity": alert.get('confidence', 'Unknown'),
                "description": alert.get('description', ''),
                "impact": alert.get('otherinfo', 'Potential security issue'),
                "mitigation": alert.get('solution', 'Follow OWASP best practices'),
                "confidence": alert.get('confidence', 'Unknown'),
                "source": "OWASP ZAP"
            }
            vulnerabilities.append(vuln)

        # Dummy headers placeholder (ZAP doesn't return headers this way)
        headers = {}

        return {
            "headers": headers,
            "vulnerabilities": vulnerabilities
        }

    except Exception as e:
        print(f"ZAP scan error: {str(e)}")
        return {
            "headers": {},
            "vulnerabilities": [],
            "error": str(e)
        }

def map_zap_severity(risk_code):
    """Map ZAP risk codes to readable severity levels"""
    mapping = {
        '3': 'High',
        '2': 'Medium',
        '1': 'Low',
        '0': 'Info'
    }
    return mapping.get(str(risk_code), 'Medium')
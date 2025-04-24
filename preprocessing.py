import json

def analyze_security_headers(headers):
    """Analyze security headers and identify potential issues"""
    header_issues = []
    
    # Check for missing important security headers
    important_headers = {
        'Content-Security-Policy': 'No Content-Security-Policy header found. This header helps prevent XSS attacks.',
        'X-Content-Type-Options': 'No X-Content-Type-Options header found. This header prevents MIME-sniffing attacks.',
        'X-Frame-Options': 'No X-Frame-Options header found. This header prevents clickjacking attacks.',
        'X-XSS-Protection': 'No X-XSS-Protection header found. This header can help prevent some XSS attacks.',
        'Strict-Transport-Security': 'No Strict-Transport-Security header found. This header enforces HTTPS connections.',
        'Referrer-Policy': 'No Referrer-Policy header found. This header controls how much referrer information is sent.'
    }
    
    for header, message in important_headers.items():
        if header not in headers:
            header_issues.append({
                'type': 'missing_header',
                'header': header,
                'message': message
            })
    
    # Check for insecure header values
    if 'X-Frame-Options' in headers and headers['X-Frame-Options'].upper() != 'DENY' and headers['X-Frame-Options'].upper() != 'SAMEORIGIN':
        header_issues.append({
            'type': 'insecure_header_value',
            'header': 'X-Frame-Options',
            'message': f"The X-Frame-Options header value '{headers['X-Frame-Options']}' might not be secure. Use DENY or SAMEORIGIN."
        })
    
    if 'X-XSS-Protection' in headers and headers['X-XSS-Protection'] != '1; mode=block':
        header_issues.append({
            'type': 'insecure_header_value',
            'header': 'X-XSS-Protection',
            'message': f"The X-XSS-Protection header value '{headers['X-XSS-Protection']}' might not be secure. Use '1; mode=block'."
        })
        
    # Check for information leakage headers
    if 'Server' in headers:
        header_issues.append({
            'type': 'information_leakage',
            'header': 'Server',
            'message': f"The Server header reveals server information: '{headers['Server']}'. This could help attackers target vulnerabilities."
        })
    
    if 'X-Powered-By' in headers:
        header_issues.append({
            'type': 'information_leakage',
            'header': 'X-Powered-By',
            'message': f"The X-Powered-By header reveals technology information: '{headers['X-Powered-By']}'. This could help attackers target vulnerabilities."
        })
    
    return header_issues

def analyze_html_elements(vulnerable_elements):
    """Analyze potentially vulnerable HTML elements"""
    element_issues = []
    
    # Check forms for security issues
    for form in vulnerable_elements.get('forms', []):
        action = form.get('action', '')
        method = form.get('method', 'GET').upper()
        
        # Check for forms with no action
        if not action:
            element_issues.append({
                'type': 'insecure_form',
                'issue': 'empty_action',
                'message': 'Form with empty action attribute found. This could lead to unintended form submissions.'
            })
        
        # Check for forms using GET method for sensitive operations
        if method == 'GET':
            element_issues.append({
                'type': 'insecure_form',
                'issue': 'get_method',
                'message': 'Form using GET method found. Sensitive operations should use POST to prevent data leakage in URLs.'
            })
    
    # Check for inline scripts
    if vulnerable_elements.get('inline_scripts', []):
        element_issues.append({
            'type': 'insecure_script',
            'issue': 'inline_script',
            'message': f'Found {len(vulnerable_elements["inline_scripts"])} inline scripts. Inline scripts can increase XSS risk and violate CSP policies.'
        })
    
    # Check for iframe security
    for iframe in vulnerable_elements.get('iframes', []):
        if not iframe.get('sandbox'):
            element_issues.append({
                'type': 'insecure_iframe',
                'issue': 'no_sandbox',
                'message': 'Found iframe without sandbox attribute. This might pose security risks.'
            })
    
    return element_issues

def run_preprocessing(crawled_data):
    """Preprocess and structure the crawled data for the model"""
    try:
        # Parse the JSON data
        data = json.loads(crawled_data)
        
        # Extract key components
        url = data.get('url', '')
        headers = data.get('headers', {})
        vulnerable_elements = data.get('vulnerable_elements', {})
        
        # Analyze headers
        header_issues = analyze_security_headers(headers)
        
        # Analyze HTML elements
        element_issues = analyze_html_elements(vulnerable_elements)
        
        # Combine all issues
        all_issues = {
            'url': url,
            'header_issues': header_issues,
            'element_issues': element_issues,
            'raw_data': {
                'headers': headers,
                'elements': vulnerable_elements
            }
        }
        
        # Create summarized text for the LLM
        summary_text = f"URL: {url}\n\n"
        
        # Add header analysis
        summary_text += "HEADER ISSUES:\n"
        if header_issues:
            for issue in header_issues:
                summary_text += f"- {issue['message']}\n"
        else:
            summary_text += "- No header issues found\n"
        
        # Add element analysis
        summary_text += "\nELEMENT ISSUES:\n"
        if element_issues:
            for issue in element_issues:
                summary_text += f"- {issue['message']}\n"
        else:
            summary_text += "- No element issues found\n"
        
        # Add raw data for context
        summary_text += "\nRAW HEADER DATA:\n"
        for header, value in headers.items():
            summary_text += f"{header}: {value}\n"
        
        summary_text += "\nFORMS FOUND:\n"
        for form in vulnerable_elements.get('forms', []):
            summary_text += f"Form Action: {form.get('action', 'None')}, Method: {form.get('method', 'None')}\n"
        
        # Return structured data and summary
        return {
            'structured_data': all_issues,
            'summary_text': summary_text
        }
    
    except Exception as e:
        print(f"Error during preprocessing: {e}")
        return {
            'structured_data': {'error': str(e)},
            'summary_text': f"Error during preprocessing: {str(e)}"
        }
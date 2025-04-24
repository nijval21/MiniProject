import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import json
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

def fetch_url(url, use_selenium=False):
    """Fetch URL content using either requests or selenium"""
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'DNT': '1',
        'Connection': 'keep-alive',
        'Upgrade-Insecure-Requests': '1',
        'Pragma': 'no-cache',
        'Cache-Control': 'no-cache',
    }
    
    if use_selenium:
        # Setup Selenium WebDriver
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)
        
        try:
            driver.get(url)
            time.sleep(3)  # Wait for page to load
            html_content = driver.page_source
            
            # Get response headers through a separate request
            response = requests.get(url, headers=headers)
            response_headers = dict(response.headers)
            
            driver.quit()
            return html_content, response_headers
        except Exception as e:
            print(f"Error with Selenium: {e}")
            driver.quit()
            return None, None
    else:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            return response.text, dict(response.headers)
        except Exception as e:
            print(f"Error with requests: {e}")
            return None, None

def extract_links(soup, base_url):
    """Extract links from soup object"""
    links = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('http') or href.startswith('/'):
            absolute_link = urljoin(base_url, href)
            links.append(absolute_link)
    return list(set(links))

def extract_security_headers(headers):
    """Extract security-related headers"""
    security_headers = {}
    important_headers = [
        'Content-Security-Policy',
        'X-Content-Type-Options',
        'X-Frame-Options',
        'X-XSS-Protection',
        'Strict-Transport-Security',
        'Referrer-Policy',
        'Feature-Policy',
        'Permissions-Policy',
        'Access-Control-Allow-Origin',
        'Server',
        'X-Powered-By'
    ]
    
    # Check for presence and values of important headers
    for header in important_headers:
        if header in headers:
            security_headers[header] = headers[header]
    
    return security_headers

def analyze_html_for_vulnerabilities(html_content):
    """Extract potentially vulnerable HTML elements"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    vulnerable_elements = {
        'forms': [],
        'inline_scripts': [],
        'external_scripts': [],
        'iframes': [],
        'meta_tags': []
    }
    
    # Extract forms
    for form in soup.find_all('form'):
        form_data = {
            'action': form.get('action', ''),
            'method': form.get('method', 'GET'),
            'inputs': []
        }
        
        for input_tag in form.find_all('input'):
            input_data = {
                'type': input_tag.get('type', ''),
                'name': input_tag.get('name', ''),
                'id': input_tag.get('id', '')
            }
            form_data['inputs'].append(input_data)
        
        vulnerable_elements['forms'].append(form_data)
    
    # Extract inline scripts
    for script in soup.find_all('script'):
        if script.string:  # Has inline content
            vulnerable_elements['inline_scripts'].append(script.string[:500])  # Limit to first 500 chars
        elif script.get('src'):  # External script
            vulnerable_elements['external_scripts'].append(script.get('src'))
    
    # Extract iframes
    for iframe in soup.find_all('iframe'):
        iframe_data = {
            'src': iframe.get('src', ''),
            'sandbox': iframe.get('sandbox', '')
        }
        vulnerable_elements['iframes'].append(iframe_data)
    
    # Extract meta tags
    for meta in soup.find_all('meta'):
        meta_data = {
            'name': meta.get('name', ''),
            'content': meta.get('content', ''),
            'http-equiv': meta.get('http-equiv', '')
        }
        vulnerable_elements['meta_tags'].append(meta_data)
    
    return vulnerable_elements

def run_crawler(url):
    """Main crawler function that returns security information about the URL"""
    print(f"Crawling {url}")
    
    # Data structures to store results
    all_data = {
        'url': url,
        'headers': {},
        'vulnerable_elements': {},
        'links': []
    }
    
    # Fetch the main URL
    html_content, headers = fetch_url(url, use_selenium=True)
    
    if html_content and headers:
        # Parse HTML
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Extract security headers
        all_data['headers'] = extract_security_headers(headers)
        
        # Extract potentially vulnerable elements
        all_data['vulnerable_elements'] = analyze_html_for_vulnerabilities(html_content)
        
        # Extract links for future crawling (optional for now)
        all_data['links'] = extract_links(soup, url)[:5]  # Limit to top 5 links
        
        # Create a summary string
        summary = f"URL: {url}\n\n"
        summary += "HEADERS:\n"
        for header, value in all_data['headers'].items():
            summary += f"{header}: {value}\n"
        
        summary += "\nVULNERABLE ELEMENTS:\n"
        summary += f"Forms: {len(all_data['vulnerable_elements']['forms'])}\n"
        summary += f"Inline Scripts: {len(all_data['vulnerable_elements']['inline_scripts'])}\n"
        summary += f"External Scripts: {len(all_data['vulnerable_elements']['external_scripts'])}\n"
        summary += f"Iframes: {len(all_data['vulnerable_elements']['iframes'])}\n"
        
        # Return the complete data
        return json.dumps(all_data, indent=2)
    else:
        return json.dumps({"error": "Failed to crawl the URL"})
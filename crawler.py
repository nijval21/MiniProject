import requests
from bs4 import BeautifulSoup
from collections import defaultdict
import json

# Security-relevant tags (matching the example code)
SECURITY_TAGS = {"meta", "script", "iframe", "link", "form", "input", "object", "embed", "a", "applet", "img", "video", "audio", "button", "textarea", "select", "base", "style"}

def fetch_url(url):
    """Fetch URL content using only requests"""
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
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        return response.text, dict(response.headers)
    except Exception as e:
        print(f"Error with requests: {e}")
        return None, None

def structure_html_content(html_content):
    """Structure HTML content similar to the parse_http_response function"""
    soup = BeautifulSoup(html_content, "html.parser")
    
    structured_body = defaultdict(list)
    for tag in soup.find_all(SECURITY_TAGS):
        tag_name = tag.name
        tag_content = tag.text.strip() if tag.text.strip() else None
        tag_attrs = tag.attrs if tag.attrs else None
        
        structured_body[tag_name].append({"content": tag_content, "attributes": tag_attrs})
    
    return dict(structured_body)

# Removed the vulnerability detection function as requested

def run_crawler(url):
    """Main crawler function that returns security information about the URL"""
    print(f"Crawling {url}")
    
    # Fetch the main URL
    html_content, headers = fetch_url(url)
    
    if html_content and headers:
        # Structure the HTML content
        structured_body = structure_html_content(html_content)
        
        # Format the results with just headers and body
        formatted_result = {
            "headers": headers,
            "body": structured_body
        }
        
        # Return the formatted results as JSON
        return json.dumps(formatted_result, indent=4)
    else:
        return json.dumps({
            "error": "Failed to crawl the URL",
            "headers": {},
            "body": {}
        }, indent=4)

# Example usage
if __name__ == "__main__":
    # Example URL for testing
    sample_url = "https://ecobloom-gdsc-challenge.web.app/"
    result = run_crawler(sample_url)
    print(result)
    
    # Optionally save to a file
    with open("structured_output.json", "w", encoding="utf-8") as f:
        f.write(result)
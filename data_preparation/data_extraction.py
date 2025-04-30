import time
import requests
import os
from zapv2 import ZAPv2

# ZAP proxy address
ZAP_URL = 'http://localhost:8080'
API_KEY = 'mkunbnbk8mf56vba68asr1gl62'  

# Directories for saving outputs
HTTP_RESPONSES_DIR = r"D:\\Minor_project\\http_responses_3"
VULNERABILITIES_DIR = r"D:\\Minor_project\\vulnerabilities_3"

# Ensure directories exist
os.makedirs(HTTP_RESPONSES_DIR, exist_ok=True)
os.makedirs(VULNERABILITIES_DIR, exist_ok=True)

def is_scanning_allowed(url):
    robots_url = url.rstrip('/') + '/robots.txt'
    try:
        response = requests.get(robots_url, timeout=5)
        if 'Disallow: /' in response.text:
            print(f"Skipping {url} due to robots.txt restrictions.")
            return False
    except requests.RequestException:
        print(f"Could not retrieve robots.txt for {url}, proceeding with scan.")
    return True

def read_urls(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        return [line.strip() for line in file.readlines() if line.strip()]

zap = ZAPv2(apikey=API_KEY, proxies={'http': ZAP_URL, 'https': ZAP_URL})
zap.core.set_option_default_user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

def scan_url(target_url, index):
    try:
        if is_scanning_allowed(target_url):
            print(f'Scanning target {target_url}...')
            zap.core.delete_all_alerts()
            zap.urlopen(target_url)

            # Wait until response is recorded in history
            timeout = 15
            start_time = time.time()
            message = None

            while time.time() - start_time < timeout:
                history= zap.core.messages()
                if history:
                    message = next((m for m in reversed(history) if target_url in m.get('requestHeader', '')), None)
                    if message.get('responseHeader') or message.get('responseBody'):
                        break
                time.sleep(1)

            if not message or not (message.get('responseHeader') or message.get('responseBody')):
                print(f"No valid response for {target_url}, skipping.")
                return

            headers = message.get('responseHeader', 'No headers retrieved')
            response_body = message.get('responseBody', 'No response body retrieved')

            if not headers.strip():
                print(f"Empty response headers for {target_url}, skipping save.")
                return
            
            error_signatures = ["502 Bad Gateway", "504 Gateway Timeout"]
            combined = f"{headers} {response_body}"

            # Check if the response contains 502 or 504 error status
            if any(err in combined for err in error_signatures):
                print(f"Invalid response (502/504) for {target_url}, skipping save.")
                return



            response_file_path = os.path.join(HTTP_RESPONSES_DIR, f"http_response_{index}.txt")
            with open(response_file_path, "w", encoding="utf-8") as response_file:
                response_file.write(f"Headers:\n{headers}\n\nResponse:\n{response_body}")

            # Passive scan
            zap.pscan.enable_all_scanners()
            time.sleep(5)
            while int(zap.pscan.records_to_scan) > 0:
                time.sleep(1)

            alerts = zap.core.alerts(baseurl=target_url)
            vuln_file_path = os.path.join(VULNERABILITIES_DIR, f"vulnerabilities_{index}.txt")
            with open(vuln_file_path, "w", encoding="utf-8") as vuln_file:
                for alert in alerts:
                    vuln_file.write(f"Name: {alert['name']}\n")
                    vuln_file.write(f"Risk: {alert['risk']}\n")
                    vuln_file.write(f"Description: {alert.get('description', 'No description available')}\n\n")

            zap.core.delete_all_alerts()

    except Exception as e:
        print(f"Error scanning {target_url}: {str(e)}")

def process_urls(file_path):
    urls = read_urls(file_path)
    for i, url in enumerate(urls, start=1):
        scan_url(url, i)

# Example usage
URL_FILE_PATH = "C:\\Users\\victus\\OneDrive\\Desktop\\info_urls.txt"
process_urls(URL_FILE_PATH)

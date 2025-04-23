import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
import time
import csv
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import re
from urllib.robotparser import RobotFileParser

def fetch_html(url):
    headers = {'User-Agent': 'Mozilla/5.0'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.text, response.headers, response.cookies
        return None, None, None
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return None, None, None

def fetch_html_with_selenium(driver, url):
    driver.get(url)
    time.sleep(3) 
    return driver.page_source

def parse_html(html):
    return BeautifulSoup(html, 'html.parser')

def extract_security_headers(headers):
    security_headers = {}
    for header in ['Content-Security-Policy', 'X-Frame-Options', 'Strict-Transport-Security', 'X-XSS-Protection']:
        if header in headers:
            security_headers[header] = headers[header]
    return security_headers

def extract_cookies(cookies):
    cookie_info = []
    for cookie in cookies:
        cookie_details = {
            'name': cookie.get('name'),
            'value': cookie.get('value'),
            'domain': cookie.get('domain'),
            'path': cookie.get('path'),
            'expiry': cookie.get('expiry', None),
            'secure': cookie.get('secure', False),
            'httpOnly': cookie.get('httpOnly', False)
        }
        cookie_info.append(cookie_details)
    return cookie_info

def extract_links(soup, base_url):
    links = []
    for link in soup.find_all('a', href=True):
        href = link['href']
        if href.startswith('http') or href.startswith('/'):  
            absolute_link = urljoin(base_url, href)
            links.append(absolute_link)
    return list(set(links))  

def extract_forms_and_js(soup):
    forms = []
    for form in soup.find_all('form'):
        form_info = {
            'action': form.get('action'),
            'method': form.get('method'),
            'inputs': [],
            'js': []
        }
        for input_tag in form.find_all('input'):
            input_info = {
                'type': input_tag.get('type'),
                'name': input_tag.get('name'),
                'value': input_tag.get('value')
            }
            form_info['inputs'].append(input_info)
        
        scripts = form.find_all('script')
        for script in scripts:
            if script.string:
                form_info['js'].append(script.string)
        
        forms.append(form_info)
    return forms

def setup_driver():
    options = Options()
    options.add_argument("--headless")  
    options.add_argument("--disable-gpu")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    return webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=options)

def fetch_data_selenium(driver, url):
    driver.get(url)
    time.sleep(3)  

    headlines = []
    links = set()
    forms_and_js = []

    for element in driver.find_elements(By.TAG_NAME, "h2"):
        headlines.append(element.text)

    for element in driver.find_elements(By.TAG_NAME, "a"):
        href = element.get_attribute("href")
        if href:
            links.add(href)

    soup = parse_html(driver.page_source)
    forms_and_js = extract_forms_and_js(soup)

    return headlines, links, forms_and_js

def save_to_txt(data, filename='output.txt'):
    with open(filename, mode='w', encoding='utf-8') as file:
        for url, html in data:
            file.write(f"URL: {url}\n")  # Write the URL
            file.write("HTML Content:\n")  # Add a label
            file.write(html)  # Write the HTML content
            file.write("\n" + "="*80 + "\n\n")  # Separator between entries
    print(f"Data saved to {filename}")

def check_robots_txt(url):
    parsed_url = urlparse(url)
    robots_url = f"{parsed_url.scheme}://{parsed_url.netloc}/robots.txt"
    rp = RobotFileParser()
    rp.set_url(robots_url)
    try:
        rp.read()
        return rp.can_fetch('*', url)  
    except Exception as e:
        print(f"Error reading robots.txt: {e}")
        return True  

def crawl(start_url, max_pages=3, use_selenium=False):
    visited = set()
    to_visit = set([start_url])
    all_html_content = []
    all_security_headers = []
    all_cookies = []
    all_forms_and_js = []

    driver = None
    if use_selenium:
        driver = setup_driver()

    try:
        while to_visit and len(visited) < max_pages:
            current_url = to_visit.pop()
            if current_url in visited:
                continue

            print(f"Crawling: {current_url}")
            html = None
            headers = None
            cookies_info = []
            forms_and_js = []
            

            if use_selenium:
                html = fetch_html_with_selenium(driver, current_url)
                if html:
                    soup = parse_html(html)
                    links = extract_links(soup, current_url)
                    forms_and_js = extract_forms_and_js(soup)

                    try:
                        response = requests.get(current_url, timeout=10)
                        headers = response.headers
                        security_headers = extract_security_headers(headers)
                    except Exception as e:
                        print(f"Error fetching headers for {current_url}: {e}")
                        security_headers = {}

                    cookies_info = extract_cookies(driver.get_cookies())
            else:
                try:
                    response = requests.get(current_url, timeout=20)
                    html = response.text
                    headers = response.headers
                    cookies = response.cookies
                    if html:
                        soup = parse_html(html)
                        links = extract_links(soup, current_url)
                        forms_and_js = extract_forms_and_js(soup)
                        security_headers = extract_security_headers(headers)
                        cookies_info = extract_cookies(cookies)
                except Exception as e:
                    print(f"Error crawling {current_url}: {e}")
                    continue

            if html is not None:
                all_html_content.append([current_url, html])
                all_security_headers.append(security_headers)
                all_cookies.extend(cookies_info)
                all_forms_and_js.extend(forms_and_js)

                soup = parse_html(html)
                links = extract_links(soup, current_url)
                to_visit.update(set(links) - visited)

            visited.add(current_url)
            time.sleep(2) 

    finally:
        if driver:
            driver.quit()

    print(f"Crawled {len(visited)} pages")
    return all_html_content, all_security_headers, all_cookies, all_forms_and_js


def run_crawler(url):
    print("Reached crawler")
    html_data, security_headers, cookies, forms_and_js = crawl(url, max_pages=10, use_selenium=True)

    output = ""

    for i in range(len(html_data)):
        output += f"\nURL: {html_data[i][0]}\n\n"
        output += f"HTML Content:\n{html_data[i][1]}\n\n"

        if i < len(security_headers):
            output += "Security Headers:\n"
            for k, v in security_headers[i].items():
                output += f"{k}: {v}\n"
            output += "\n"

    output += "\nCookies:\n"
    for cookie in cookies:
        output += f"{cookie}\n"

    output += "\nForms and JavaScript:\n"
    for form in forms_and_js:
        output += f"{form}\n"

    return output
    

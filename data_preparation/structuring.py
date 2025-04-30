import os
import json
import re
from bs4 import BeautifulSoup
from collections import defaultdict

# Security-relevant tags
SECURITY_TAGS = {"meta", "script", "iframe", "link", "form", "input", "object", "embed", "a", "applet", "img", "video", "audio", "button", "textarea", "select", "base", "style"}

def parse_http_response(response_path, vuln_path):
    with open(response_path, "r", encoding="utf-8") as f:
        raw_data = f.read()

    with open(vuln_path, "r", encoding="utf-8") as f:
        vulnerabilities = f.read().strip().split("\n\n")

    headers_match = re.search(r"Headers:\n(.*?)\n\nResponse:\n(.*)", raw_data, re.DOTALL)
    if not headers_match:
        raise ValueError(f"Invalid HTTP response format in {response_path}")

    headers_section = headers_match.group(1)
    body_section = headers_match.group(2)

    header_dict = {}
    for line in headers_section.split("\n"):
        if ": " in line:
            key, value = line.split(": ", 1)
            header_dict[key] = value

    soup = BeautifulSoup(body_section, "html.parser")

    structured_body = defaultdict(list)
    for tag in soup.find_all(SECURITY_TAGS):
        tag_name = tag.name
        tag_content = tag.text.strip() if tag.text.strip() else None
        tag_attrs = tag.attrs if tag.attrs else None

        structured_body[tag_name].append({"content": tag_content, "attributes": tag_attrs})

    structured_vulnerabilities = []
    for v in vulnerabilities:
        lines = v.split("\n")
        if len(lines) >= 3:
            name = lines[0].replace("Name: ", "").strip()
            risk = lines[1].replace("Risk: ", "").strip()
            description = " ".join(lines[2:]).replace("Description: ", "").strip()
            structured_vulnerabilities.append({"type": name, "severity": risk, "description": description})
        else:
            structured_vulnerabilities.append({"type": "Unknown", "severity": "Unknown", "description": "No description available"})

    return {
        "headers": header_dict,
        "body": dict(structured_body),
        "vulnerabilities": structured_vulnerabilities
    }

def process_all_folders(main_folder, output_folder):
    os.makedirs(output_folder, exist_ok=True)

    for folder_num in range(1, 5):
        response_folder = os.path.join(main_folder, f"http_responses_{folder_num}")
        vuln_folder = os.path.join(main_folder, f"vulnerabilities_{folder_num}")

        if not os.path.isdir(response_folder) or not os.path.isdir(vuln_folder):
            print(f"Skipping missing folder pair {folder_num}")
            continue

        response_files = sorted(os.listdir(response_folder))
        vuln_files = sorted(os.listdir(vuln_folder))

        response_files_dict = {f.split("_")[-1].split(".")[0]: f for f in response_files if f.startswith("http_response")}
        vuln_files_dict = {f.split("_")[-1].split(".")[0]: f for f in vuln_files if f.startswith("vulnerabilities")}

        common_file_ids = set(response_files_dict.keys()) & set(vuln_files_dict.keys())

        for file_id in common_file_ids:
            response_path = os.path.join(response_folder, response_files_dict[file_id])
            vuln_path = os.path.join(vuln_folder, vuln_files_dict[file_id])

            try:
                structured_output = parse_http_response(response_path, vuln_path)
                output_filename = f"structured_code_{folder_num}_{file_id}.json"
                output_path = os.path.join(output_folder, output_filename)

                with open(output_path, "w", encoding="utf-8") as f:
                    json.dump(structured_output, f, indent=4)

                print(f"Saved structured JSON to {output_path}")

            except Exception as e:
                print(f"Error processing file ID {file_id} in folder {folder_num}: {e}")

# Example Usage
main_folder = "D:\\Minor_project"  # update with your path
output_folder = "C:\\Users\\victus\\OneDrive\\Desktop\\structured_outputs"

process_all_folders(main_folder, output_folder)

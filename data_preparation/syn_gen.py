import os
import json
import copy

def augment_data(data, output_dir, filename_base):
    augmentations = []
    headers = data.get("headers", {}).copy()
    body = data.get("body", "")
    vulnerabilities = data.get("vulnerabilities", []).copy()

    rules = [
        ("Missing Anti-clickjacking Header", "X-Frame-Options", "DENY"),
        ("Content Security Policy (CSP) Header Not Set", "Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none';"),
        ("X-Content-Type-Options Header Missing", "X-Content-Type-Options", "nosniff"),
        ("Strict Transport Security Header Missing", "Strict-Transport-Security", "max-age=31536000; includeSubDomains"),
        ("Referrer Policy Header Missing", "Referrer-Policy", "no-referrer"),
        ("Permissions Policy Header Missing", "Permissions-Policy", "geolocation=(), camera=(), microphone=()"),
    ]

    for vuln_name, header_field, header_value in rules:
        if any(vuln_name in v["type"] for v in vulnerabilities):
            modified_data = copy.deepcopy(data)
            modified_data["headers"][header_field] = header_value
            modified_data["vulnerabilities"] = [v for v in vulnerabilities if vuln_name not in v["type"]]
            augmentations.append(modified_data)

    header_removal_rules = [
        ("Server Leaks Version Information via \"Server\" HTTP Response Header Field", "Server"),
        ("Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field", "X-Powered-By"),
        ("X-AspNet-Version Header Information Leak", "X-AspNet-Version"),
    ]

    for vuln_name, header_field in header_removal_rules:
        if any(vuln_name in v["type"] for v in vulnerabilities):
            modified_data = copy.deepcopy(data)
            modified_data["headers"].pop(header_field, None)
            modified_data["vulnerabilities"] = [v for v in vulnerabilities if vuln_name not in v["type"]]
            augmentations.append(modified_data)

    if any("Cross-Domain JavaScript Source File Inclusion" in v["type"] for v in vulnerabilities):
        modified_data = copy.deepcopy(data)
        modified_data["body"] = remove_script_tags(modified_data["body"])
        modified_data["vulnerabilities"] = [v for v in vulnerabilities if "Cross-Domain JavaScript Source File Inclusion" not in v["type"]]
        augmentations.append(modified_data)

    if any("Cookie No HttpOnly Flag" in v["type"] or "Cookie without SameSite Attribute" in v["type"] for v in vulnerabilities):
        modified_data = copy.deepcopy(data)
        modified_data["headers"]["Set-Cookie"] = "Secure; HttpOnly; SameSite=Strict"
        modified_data["vulnerabilities"] = [v for v in vulnerabilities if "Cookie No HttpOnly Flag" not in v["type"] and "Cookie without SameSite Attribute" not in v["type"]]
        augmentations.append(modified_data)

    os.makedirs(output_dir, exist_ok=True)
    for i, aug_data in enumerate(augmentations):
        output_path = os.path.join(output_dir, f"{filename_base}_aug{i+1}.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(aug_data, f, indent=4)
        print(f"Saved: {output_path}")

def remove_script_tags(data):
    if isinstance(data, dict):
        return {k: remove_script_tags(v) for k, v in data.items() if k.lower() not in ["script", "scripts"]}
    elif isinstance(data, list):
        return [remove_script_tags(item) for item in data]
    return data

def main(input_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    files = [f for f in os.listdir(input_dir) if f.endswith(".json")]

    for file in files:
        input_path = os.path.join(input_dir, file)
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        
        filename_base = os.path.splitext(file)[0]
        augment_data(data, output_dir, filename_base)

if __name__ == "__main__":
    input_folder = "C:\\Users\\victus\\OneDrive\\Desktop\\structured_outputs"  # <-- CHANGE this to your input folder
    output_folder = "C:\\Users\\victus\\OneDrive\\Desktop\\Augmented Data"  # <-- CHANGE this to your output folder

    main(input_folder, output_folder)

import os
import json

def convert_folder_to_jsonl(input_folder, output_file):
    data_points = []

    for filename in os.listdir(input_folder):
        if filename.endswith(".json"):
            filepath = os.path.join(input_folder, filename)
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            
            # Prepare prompt
            headers = data.get("headers", {})
            body = data.get("body", {})
            prompt = f"Headers: {json.dumps(headers)}\nBody: {json.dumps(body)}\n"

            # Prepare completion
            vulnerabilities = data.get("vulnerabilities", [])
            completion_parts = []
            for vuln in vulnerabilities:
                vuln_type = vuln.get("type", "Unknown")
                severity = vuln.get("severity", "Unknown")
                description = vuln.get("description", "")
                completion_parts.append(f"{vuln_type} ({severity}): {description}")
            
            if not completion_parts:
                completion = "No vulnerabilities found."
            else:
                completion = "\n".join(completion_parts)

            # Add to data points
            data_points.append({
                "prompt": prompt,
                "completion": completion
            })

    # Write to JSONL
    with open(output_file, "w", encoding="utf-8") as f_out:
        for dp in data_points:
            f_out.write(json.dumps(dp, ensure_ascii=False) + "\n")

    print(f"✅ Successfully created {output_file} with {len(data_points)} examples!")

# Example usage:
input_folder = r"C:\\Users\\victus\\OneDrive\\Desktop\\Data_final"
output_jsonl = r"C:\Users\victus\OneDrive\Desktop\fine_tuning_data.jsonl"

convert_folder_to_jsonl(input_folder, output_jsonl)

import json

def add_delimiter_to_dataset(input_path, output_path):
    with open(input_path, 'r', encoding='utf-8') as infile, open(output_path, 'w', encoding='utf-8') as outfile:
        for line in infile:
            record = json.loads(line.strip())
            if '###' not in record['prompt']:
                record['prompt'] = record['prompt'].strip() + '\n###'
            json.dump(record, outfile, ensure_ascii=False)
            outfile.write('\n')

# Example usage:
add_delimiter_to_dataset("dataset.jsonl", "dataset_with_delimiter.jsonl")

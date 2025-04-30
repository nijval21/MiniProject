import torch
from datasets import Dataset
from transformers import Trainer, TrainingArguments, T5ForConditionalGeneration, T5Tokenizer
from peft import get_peft_model, LoraConfig
import pandas as pd
import json
from sklearn.model_selection import train_test_split
import warnings
from nltk.translate.bleu_score import sentence_bleu
import evaluate
import numpy as np
import os

warnings.filterwarnings("ignore")

# Load data function
def load_data(filepath):
    data = {"prompt": [], "completion": []}
    with open(filepath, 'r') as f:
        for line in f:
            record = json.loads(line.strip())
            data["prompt"].append(record['prompt'])
            data["completion"].append(record['completion'])
    return Dataset.from_dict(data)

# Read full dataset and split
dataset = load_data("dataset_with_delimiter.jsonl")
df = pd.DataFrame(dataset)
_, test_df = train_test_split(df, test_size=0.1, random_state=42)
test_data = Dataset.from_pandas(test_df)

# Load tokenizer
tokenizer = T5Tokenizer.from_pretrained("t5-base")

# Load model and LoRA
model = T5ForConditionalGeneration.from_pretrained("./t5_vuln_classifier/checkpoint-136")
model.gradient_checkpointing_enable()

lora_config = LoraConfig(
    r=8,
    lora_alpha=32,
    target_modules=["q", "k", "v"],
    lora_dropout=0.1,
    bias="none"
)
model = get_peft_model(model, lora_config)

# Move model to device (CPU or GPU)
device = torch.device("cuda") if torch.cuda.is_available() else torch.device("cpu")
model.to(device)
model.eval()

# Tokenize function with reduced max_length for consistency
def tokenize_function(examples):
    inputs = examples['prompt']
    targets = examples['completion']
    model_inputs = tokenizer(inputs, padding="max_length", truncation=True, max_length=64)
    labels = tokenizer(targets, padding="max_length", truncation=True, max_length=64)
    model_inputs["labels"] = labels["input_ids"]
    return model_inputs

# Pre-tokenize test data (if needed)
test_data = test_data.map(tokenize_function, batched=True)

# Define evaluation metrics
rouge = evaluate.load("rouge")
bleu_scores = []
exact_matches = []

# Evaluation loop
print("starting evaluation:")
predictions = []
references = []
counter = 1
for example in test_data:
    # Tokenize each example with max_length to prevent OOM
    print("--------------------------------------------------------------")
    inputs = tokenizer(
        example['prompt'],
        return_tensors="pt",
        padding="max_length",
        truncation=True,
        max_length=64
    ).to(device)
    with torch.no_grad():
        outputs = model.generate(
            **inputs,
            max_length=64,
            num_beams=1  # single beam to reduce memory
        )

    pred = tokenizer.decode(outputs[0], skip_special_tokens=True)
    label = example['completion']
    print("Prompt: ",example['prompt'])
    print("Prediction:", pred)
    predictions.append(pred)
    references.append(label)
    print(f"example {counter} done!")
    counter+=1
    print("--------------------------------------------------------------")

    # BLEU Score
    bleu_scores.append(sentence_bleu([label.split()], pred.split()))
    # Exact Match
    exact_matches.append(int(pred.strip() == label.strip()))

# Compute final metrics
results = {
    "Exact Match Accuracy": np.mean(exact_matches),
    "Average BLEU Score": np.mean(bleu_scores),
}
# Add ROUGE
rouge_out = rouge.compute(predictions=predictions, references=references)
results.update({
    "ROUGE-1": rouge_out["rouge1"],
    "ROUGE-2": rouge_out["rouge2"],
    "ROUGE-L": rouge_out["rougeL"],
})

# Save the results
os.makedirs("./results_eval", exist_ok=True)
with open("./results_eval/eval_results.json", "w") as f:
    json.dump(results, f, indent=4)

print("Evaluation completed. Metrics saved to 'results_eval/eval_results.json'.")

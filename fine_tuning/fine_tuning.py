import torch
from datasets import load_dataset, Dataset
from transformers import (
    Trainer, TrainingArguments, 
    T5ForConditionalGeneration, T5Tokenizer
)
from peft import get_peft_model, LoraConfig
from sklearn.model_selection import train_test_split
import logging
import json
import pandas as pd
import warnings
warnings.filterwarnings("ignore")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load data function with validation
def load_data(filepath):
    data = {"prompt": [], "completion": []}
    with open(filepath, 'r') as f:
        for i, line in enumerate(f):
            try:
                record = json.loads(line.strip())
                # Validate keys
                if 'prompt' not in record or 'completion' not in record:
                    logger.warning(f"Line {i+1}: Missing required keys. Skipping.")
                    continue
                
                # Check for empty values
                if not record['prompt'] or not record['completion']:
                    logger.warning(f"Line {i+1}: Empty prompt or completion. Skipping.")
                    continue
                
                data["prompt"].append(record['prompt'])
                data["completion"].append(record['completion'])
            except json.JSONDecodeError:
                logger.warning(f"Line {i+1}: Invalid JSON format. Skipping.")
                continue
    
    logger.info(f"Loaded {len(data['prompt'])} valid examples")
    
    # Print a few examples to verify data format
    for i in range(min(3, len(data['prompt']))):
        logger.info(f"Example {i+1}:")
        logger.info(f"  Prompt: {data['prompt'][i][:100]}...")
        logger.info(f"  Completion: {data['completion'][i]}")
    
    return Dataset.from_dict(data)

# Load the data
logger.info("Loading data...")
train_data = load_data("dataset_with_delimiter.jsonl")

# Convert Hugging Face Dataset to pandas DataFrame
df = pd.DataFrame(train_data)

# Split the data
train_df, val_df = train_test_split(df, test_size=0.2, random_state=42)

# Convert back to Hugging Face Dataset
train_data = Dataset.from_pandas(train_df)
val_data = Dataset.from_pandas(val_df)

logger.info(f"Train size: {len(train_data)}, Validation size: {len(val_data)}")

# Load tokenizer and model
logger.info("Loading tokenizer and model...")
tokenizer = T5Tokenizer.from_pretrained("t5-base")
model = T5ForConditionalGeneration.from_pretrained("t5-base")

# Enable gradient checkpointing to save memory
model.gradient_checkpointing_enable()

# Create LoRA config
lora_config = LoraConfig(
    r=16,  # Increased rank for better representation
    lora_alpha=32,
    target_modules=["q", "k", "v", "o"],  # Added output projection
    lora_dropout=0.1,
    bias="none"
)

# Apply LoRA
model = get_peft_model(model, lora_config)
logger.info(f"Trainable parameters: {model.print_trainable_parameters()}")

# Better tokenization function with proper handling of T5 format
def tokenize_function(examples):
    # T5 expects inputs in format: "task: text"
    # Make sure the prompt format is correct
    inputs = examples['prompt']
    targets = examples['completion']
    
    # Tokenize inputs
    model_inputs = tokenizer(
        inputs, 
        padding="max_length", 
        truncation=True, 
        max_length=384,  # Increased for more context
        return_tensors="pt"
    )
    
    # Tokenize targets
    with tokenizer.as_target_tokenizer():
        labels = tokenizer(
            targets,
            padding="max_length",
            truncation=True,
            max_length=128,  # Reduced for targets which are typically shorter
            return_tensors="pt"
        )
    
    # Replace padding token id with -100 for loss calculation
    labels = labels["input_ids"].masked_fill_(
        labels["input_ids"] == tokenizer.pad_token_id, -100
    )
    
    model_inputs["labels"] = labels
    return model_inputs

# Tokenizing datasets
logger.info("Tokenizing datasets...")
train_tokenized = train_data.map(tokenize_function, batched=True, remove_columns=train_data.column_names)
val_tokenized = val_data.map(tokenize_function, batched=True, remove_columns=val_data.column_names)

# Training arguments
training_args = TrainingArguments(
    output_dir='./t5_vuln_classifier',
    logging_dir='./t5_logs',
    logging_steps=100,
    per_device_train_batch_size=4,  # Increased but still memory-friendly
    per_device_eval_batch_size=4,
    gradient_accumulation_steps=4,  # Simulate batch size 16
    num_train_epochs=5,  # More epochs for better learning
    save_strategy="epoch",
    save_total_limit=2,
    # Keep basic validation during training
    eval_strategy="epoch",
    eval_steps=500,
    load_best_model_at_end=False,  # Removed best model loading since we don't have a suitable metric
    fp16=True,
    report_to="tensorboard",
    learning_rate=5e-4,  # Reasonable learning rate for fine-tuning
    warmup_ratio=0.1,  # Warmup for stability
)

# Trainer
trainer = Trainer(
    model=model,
    args=training_args,
    train_dataset=train_tokenized,
    eval_dataset=val_tokenized,
)

# Train
logger.info("Starting training...")
trainer.train()

# Save model
logger.info("Saving the model...")
trainer.save_model()
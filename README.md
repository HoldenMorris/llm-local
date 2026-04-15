# LLM Spam Detection Benchmark

Local benchmarking tool for testing SLM (Small Language Model) spam detection accuracy against a corpus of labeled emails.

## Quick Start

```bash
# Run benchmark with default model and prompt
./benchmark.sh

# Specify model
./benchmark.sh gemma2:2b

# Use custom prompt
./benchmark.sh qwen2.5:0.5b prompts/detailed.txt

# View results
./show_results.sh
```

## Project Structure

```
├── benchmark.sh          # Main benchmark script
├── llm-test.sh           # Single-email test script
├── show_results.sh       # Display results table
├── prompts/              # System prompts for classification
│   ├── default.txt
│   ├── detailed.txt
│   └── concise.txt
├── test-corpus/          # Labeled .eml test files
│   ├── spam_high/        # Obvious spam (lottery, scams)
│   ├── spam_low/         # Mild spam (promotional)
│   ├── phishing/         # Credential phishing
│   ├── whale_phishing/   # CEO/CFO fraud targeting
│   ├── dangerous/        # Malware delivery attempts
│   └── clean/            # Legitimate emails
└── results/              # CSV benchmark results
```

## Adding Test Emails

Create `.eml` files in the appropriate category folder:

```bash
# Example: Add a new spam sample
vim test-corpus/spam_high/04_new_spam.eml
```

Format:
```
From: sender@example.com
To: victim@email.com
Subject: Email Subject

Email body content here...
```

## Creating New Prompts

```bash
# Create a new prompt
vim prompts/my_prompt.txt

# Test with the new prompt
./benchmark.sh qwen2.5:0.5b prompts/my_prompt.txt
```

## Test Corpus Categories

| Category | Expected | Description |
|----------|----------|-------------|
| spam_high | SPAM | Obvious scams (lottery, Nigerian prince) |
| spam_low | SPAM | Mild spam (promotional deals) |
| phishing | SPAM | Credential harvesting attempts |
| whale_phishing | SPAM | Executive fraud targeting |
| dangerous | SPAM | Malware delivery attempts |
| clean | HAM | Legitimate business emails |

## Results Format

Results are stored in `results/benchmark_results.csv`:

```csv
timestamp,model,prompt,total,correct,accuracy,avg_time
2026-04-15 12:34:22,qwen2.5:0.5b,default,20,15,75.0%,1.14s
```

## Tested Models

| Model | Accuracy | Speed | Notes |
|-------|----------|-------|-------|
| qwen2.5:0.5b | 75% | ~1s | Fast, lightweight |
| gemma2:2b | 80% | ~4s | Better accuracy, slower |
| phi3:3.8b | - | - | Not yet tested |
| llama3.2:1b | - | - | Not yet tested |

## Requirements

- Docker with Ollama image
- `jq` for JSON parsing (optional, falls back to grep)
- `bc` for floating point math
- Model pulled in Ollama (auto-downloaded on first run)

## Troubleshooting

**Model not downloading:**
```bash
docker exec llm-spam-test ollama pull qwen2.5:0.5b
```

**Container issues:**
```bash
docker rm -f llm-spam-test
./benchmark.sh
```

**View raw API response:**
```bash
curl -s -X POST http://localhost:11434/api/generate -d '{"model":"qwen2.5:0.5b","prompt":"test","stream":false}'
```

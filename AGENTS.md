# AGENTS.md

## Project Overview

This is a local LLM spam detection benchmarking toolkit. It tests SLMs (Small Language Models) against a labeled corpus of `.eml` files to measure classification accuracy.

## Key Files

| File | Purpose |
|------|---------|
| `benchmark.sh` | Main script - runs full test suite against corpus |
| `llm-test.sh` | Single email test with detailed output |
| `show_results.sh` | Renders results table from CSV |
| `prompts/*.txt` | System prompts - modify these to improve accuracy |
| `test-corpus/*/` | Labeled test emails organized by category |
| `results/*.csv` | Benchmark results stored for comparison |

## How the Benchmark Works

1. Reads all `.eml` files from `test-corpus/` categories
2. Extracts email body text
3. Sends to Ollama API with system prompt + email content
4. Parses response for "SPAM" or "HAM"
5. Compares against expected category label
6. Calculates accuracy and timing metrics
7. Appends results to CSV

## Adding Test Cases

1. Create `.eml` file in appropriate `test-corpus/` subdirectory
2. Use realistic email format (From, Subject, Body)
3. Ensure category matches expected classification
4. Run benchmark to include in results

## Improving Accuracy

If a model performs poorly:

1. **Try different prompts** - Edit files in `prompts/`
2. **Add more test cases** - Especially false positives/negatives
3. **Try larger models** - gemma2:2b > qwen2.5:0.5b
4. **Adjust num_predict** - Higher values may reduce truncation

## Running Tests

```bash
# Basic benchmark
./benchmark.sh

# Specific model
./benchmark.sh gemma2:2b

# With prompt
./benchmark.sh qwen2.5:0.5b prompts/detailed.txt

# Single test
./llm-test.sh qwen2.5:0.5b
```

## Common Issues

| Issue | Solution |
|-------|----------|
| Empty detection | Check API response format, model may be overloaded |
| Slow inference | Normal for first run; model loads once then stays warm |
| Model not found | Container downloads automatically, or pull manually |
| Container conflicts | `docker rm -f llm-spam-test` then rerun |

## Performance Targets

- **Accuracy**: >85% is good, >95% is excellent
- **Speed**: <2s per email is acceptable for SLMs
- **False positives**: Minimize clean emails classified as spam

## Prompt Engineering Tips

- Be explicit: "Respond with exactly SPAM or HAM"
- Include spam indicators: urgency, links, requests for info
- Test prompts with both true positives and true negatives
- Temperature 0.0 for deterministic results

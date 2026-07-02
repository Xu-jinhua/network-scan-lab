# network-scan-lab

Experimental network scan aggregation pipeline. It runs several scanner
adapters against one or more authorized web targets, preserves the raw scanner
artifacts, and uses an OpenAI-compatible LLM API to integrate the evidence into
a structured JSON report.

## Project Layout

- `scanlab`: one-command wrapper for scanner build, scan execution, and LLM integration
- `scanner/`: scanner container image and scanner runner
- `integrator/`: LLM-based integration pipeline
- `lab/compose.yaml`: optional local vulnerable lab
- `targets.example.yaml`: example multi-target input file

## Requirements

- A URL, domain, or IP address that you are authorized to scan
- Podman or Docker
- Python 3.12 or Python 3
- An OpenAI-compatible LLM API endpoint

Install the Python dependencies:

```bash
git clone git@github.com:Xu-jinhua/network-scan-lab.git
cd network-scan-lab
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r integrator/requirements.txt
```

## Quick Start

Run a scan and integration with an OpenAI-compatible API:

```bash
./scanlab \
  --target https://example.com \
  --llm-server https://your-llm.example/v1 \
  --api-key "your-api-key" \
  --model your-model-name \
  --results-dir results/example
```

Multiple targets can be scanned by repeating `--target`:

```bash
./scanlab \
  --target https://app.example.com \
  --target https://api.example.com \
  --llm-server https://your-llm.example/v1 \
  --api-key "your-api-key" \
  --model your-model-name \
  --results-dir results/example
```

You can also provide a target file:

```bash
./scanlab --targets-file targets.example.yaml --results-dir results/batch
```

The scanner image is built automatically on the first run and reused on later
runs. Rebuild it after changing scanner tooling or `scanner/Dockerfile`:

```bash
./scanlab --target https://example.com --rebuild --results-dir results/example
```

## Local LLM

The default integration endpoint is:

```text
http://127.0.0.1:8000/v1
```

The default model is:

```text
unsloth/gemma-4-E4B-it-qat-GGUF:UD-Q4_K_XL
```

Install or build `llama.cpp` with CUDA support, make sure `llama-server` is in
your `PATH`, then start the local server:

```bash
llama-server \
  -hf unsloth/gemma-4-E4B-it-qat-GGUF:UD-Q4_K_XL \
  --host 127.0.0.1 \
  --port 8000 \
  -c 65536 \
  -ngl all \
  -fa auto \
  --reasoning off \
  --chat-template-kwargs '{"enable_thinking":false}'
```

Then run:

```bash
./scanlab \
  --target https://example.com \
  --results-dir results/example-local
```

## Optional Demo Lab

The repository includes a local vulnerable lab with Juice Shop, WebGoat, DVWA,
and VAmPI.

Start it with Podman Compose:

```bash
podman-compose -f lab/compose.yaml up -d
```

Or with Docker Compose:

```bash
docker compose -f lab/compose.yaml up -d
```

Run a single-target WebGoat test against the lab:

```bash
./scanlab \
  --target http://172.28.0.11:8080/WebGoat \
  --network scanlab \
  --results-dir results/webgoat-local
```

Run all demo targets:

```bash
./scanlab \
  --targets-file lab/targets.example.yaml \
  --network scanlab \
  --results-dir results/lab
```

Stop the lab:

```bash
podman-compose -f lab/compose.yaml down
```

or:

```bash
docker compose -f lab/compose.yaml down
```

The `--network scanlab` option attaches the scanner container to the same
container network as the lab targets, so it can reach addresses such as
`172.28.0.11`.

## Output

For `--results-dir results/example`, the pipeline writes:

- `results/example/<run_id>/aggregated_scan.json`: raw aggregated scanner output
- `results/example/latest/aggregated_scan.json`: latest raw aggregated scanner output
- `results/example/final_report.json`: LLM-integrated report
- `results/example/<run_id>/<target>/<tool>/`: per-tool raw artifacts and logs

The final report has this high-level shape:

```json
{
  "metadata": {},
  "assets": {
    "172.28.0.11": {
      "8080": {
        "sql_injection_webgoat_register_mvc_high": {
          "path": "/WebGoat/register.mvc",
          "tools": {
            "zaproxy": "SQL injection may be possible in POST request."
          },
          "description": "SQL injection may be possible in the registration endpoint.",
          "vulnerability": "SQL Injection",
          "severity": "High",
          "affected_targets": ["/WebGoat/register.mvc"]
        }
      }
    }
  }
}
```

## Scanner Profiles

Default profile:

- `nmap`
- `nikto`
- `zaproxy`
- `ffuf`
- `metasploit-framework`
- `whatweb`
- `httpx`
- `dirb`

Additional tools are installed in the scanner image but are not part of the
default profile because they need target-specific data or preconditions:

- `gobuster`
- `testssl.sh`
- `sqlmap`
- `nuclei`
- `subfinder`
- `amass`

Use another profile when needed:

```bash
./scanlab --target https://example.com --profile old --results-dir results/old-profile
./scanlab --target https://example.com --profile all --results-dir results/all-profile
```

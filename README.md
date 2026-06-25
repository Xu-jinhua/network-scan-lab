# network-scan-lab

Clean rebuild of the scan/integration prototype.

## Layout

- `lab/compose.yaml`: multi-target vulnerable lab with stable IPs
- `scanner/`: scanner container image and runner
- `integrator/`: local LLM integration pipeline
- `flake.nix` + `.envrc`: project shell, like `rice-disease-paper`

## First targets

- Juice Shop
- WebGoat
- DVWA
- VAmPI

## Tool set

The current default scan profile keeps the old project baseline and adds only
stable adapters from the rebuild:

- `nmap`
- `nikto`
- `zaproxy`
- `ffuf`
- `metasploit-framework`
- `whatweb`
- `httpx`
- `dirb`

The old project baseline is still available as `just scan-old`:

- `nmap`
- `nikto`
- `zaproxy`
- `ffuf`
- `metasploit-framework`

Optional tools are installed in the scanner image but not part of the default
profile because they need target-specific preconditions or extra data:

- `gobuster`
- `testssl.sh`
- `sqlmap`
- `nuclei`
- `subfinder`
- `amass`

Rationale:

- `nuclei` requires templates. A scanner image without templates now records a
  skipped result instead of producing an empty `nuclei.jsonl`.
- `subfinder` and `amass` are domain enumeration tools, so IP-only lab targets
  are skipped.
- `testssl.sh` only runs on TLS targets.
- `sqlmap` only runs when the target has query/post parameters or explicit
  `sqlmap_targets`.
- `gobuster` is useful, but redirect/login wildcard behavior makes it noisy on
  targets such as WebGoat unless the baseline filter is correct.

## Workflow

```bash
cd ~/Projects/network-scan-lab
direnv allow
just build-scanner
just up
just serve-llm
just scan
just integrate
```

`just serve-llm` now starts a GPU-backed `llama.cpp` server with Gemma 4 E4B QAT
and a 64k context window by default.

Useful scan variants:

```bash
just scan                  # default profile
just scan-all              # default + optional tools
just scan-old              # old project baseline only
just scan lab/targets.example.yaml all
```

The lab targets are Docker/Podman containers from `lab/compose.yaml`. The
scanner is also a container (`scanner/Dockerfile`) and `just scan` runs it on
the same `scanlab` network. The host `ports:` entries in the compose file expose
only selected services to the host, but they do not limit scanner-to-target
traffic inside the bridge network. Inside `scanlab`, the scanner reaches the
target containers by their fixed IPs and scans whatever ports are actually open
inside those containers.

Model notes:

- Default integration model: `unsloth/gemma-4-E4B-it-qat-GGUF:UD-Q4_K_XL`
- Backend: `llama.cpp` with CUDA offload
- Thinking is disabled for the JSON integration step

## Data Shape

The scanner writes per-tool artifacts first and then creates:

- `runs/<run_id>/aggregated_scan.json`
- `runs/latest/aggregated_scan.json`

The aggregate keeps summaries, artifact metadata, and raw output payloads under
each tool result so that later LLM processing can do the integration, filtering,
deduplication, and semantic merge.

`just integrate` writes `reports/final_report.json` in this shape:

```json
{
  "metadata": {},
  "assets": {
    "172.28.0.10": {
      "3000": {
        "missing_csp_header": {
          "path": "service",
          "tools": {
            "nmap": "Port 3000 is open."
          },
          "description": "Port 3000 is open.",
          "vulnerability": "Open service",
          "severity": "Informational",
          "affected_targets": ["service"]
        }
      }
    }
  }
}
```

## Why this split

- System config handles Podman.
- The local model server starts on demand from the project.
- Project config handles the lab, scanner image, and integration pipeline.

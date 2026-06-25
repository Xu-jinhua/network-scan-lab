set shell := ["bash", "-eu", "-o", "pipefail", "-c"]

default:
    just --list

up:
    podman-compose -f lab/compose.yaml up -d

down:
    podman-compose -f lab/compose.yaml down

build-scanner:
    podman build -t network-scan-scanner scanner

scan TARGETS_FILE="lab/targets.example.yaml" PROFILE="default":
    mkdir -p runs
    podman run --rm --network scanlab -v "$PWD:/work" -v "$PWD/runs:/app/runs" network-scan-scanner --targets-file "/work/{{TARGETS_FILE}}" --output-dir /app/runs --profile {{PROFILE}}

integrate INPUT="runs/latest/aggregated_scan.json":
    mkdir -p reports
    python3.12 integrator/integrate.py --input {{INPUT}}

scan-all TARGETS_FILE="lab/targets.example.yaml":
    just scan {{TARGETS_FILE}} all

scan-old TARGETS_FILE="lab/targets.example.yaml":
    just scan {{TARGETS_FILE}} old

serve-llm MODEL_REF="unsloth/gemma-4-E4B-it-qat-GGUF:UD-Q4_K_XL" PORT="8000" CTX_SIZE="65536" GPU_LAYERS="all":
    nix shell .#llama-cpp-cuda -c llama-server -hf {{MODEL_REF}} --host 127.0.0.1 --port {{PORT}} -c {{CTX_SIZE}} -ngl {{GPU_LAYERS}} -fa auto --reasoning off --chat-template-kwargs '{"enable_thinking":false}'

shell:
    nix develop

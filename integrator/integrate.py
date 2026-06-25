#!/usr/bin/env python3
import argparse
import hashlib
import json
import sys
import time
from collections import defaultdict
from copy import deepcopy
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from openai import OpenAI

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prompts import (
    PROMPT_CLUSTER_INTEGRATION,
    PROMPT_FINDING_RELEVANCE,
    PROMPT_PORT_DEDUP,
    PROMPT_RECORD_NORMALIZATION,
)


ALLOWED_SEVERITIES = [
    "Critical",
    "High",
    "Medium",
    "Low",
    "Informational",
    "Unknown",
]
ALLOWED_KINDS = ["service", "endpoint", "finding"]
DEFAULT_MODEL = "unsloth/gemma-4-E4B-it-qat-GGUF:UD-Q4_K_XL"
DEFAULT_BASE_URL = "http://127.0.0.1:8000/v1"

SIGNAL_KEYS = {
    "port",
    "portid",
    "protocol",
    "service",
    "product",
    "version",
    "url",
    "uri",
    "path",
    "status",
    "msg",
    "alert",
    "name",
    "riskcode",
    "riskdesc",
    "evidence",
    "references",
    "banner",
    "method",
    "title",
    "summary",
    "location",
    "state",
    "cweid",
    "cve",
    "plugin",
    "plugins",
}

MAX_RAW_TEXT_CHARS = 12000
MAX_RAW_LIST_ITEMS = 8
MAX_RAW_DICT_KEYS = 30
MAX_TEXT_CANDIDATES = 24


def load_bundle(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def build_client(base_url: str, api_key: str) -> OpenAI:
    return OpenAI(base_url=base_url, api_key=api_key)


def safe_str(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def target_ip(target: Dict[str, Any]) -> str:
    return safe_str(target.get("ip") or target.get("host") or "unknown")


def target_host(target: Dict[str, Any]) -> str:
    return safe_str(target.get("host") or target.get("ip") or "unknown")


def target_port(target: Dict[str, Any]) -> str:
    if target.get("port") is not None:
        return safe_str(target.get("port"))
    parsed = urlparse(safe_str(target.get("url")))
    if parsed.port:
        return str(parsed.port)
    if parsed.scheme == "https":
        return "443"
    return "80"


def target_url(target: Dict[str, Any]) -> str:
    url = safe_str(target.get("url"))
    if url:
        return url
    host = target_host(target)
    port = target_port(target)
    scheme = "https" if port in {"443", "8443"} else "http"
    return f"{scheme}://{host}:{port}"


def truncate_value(value: Any, max_depth: int = 8) -> Any:
    if max_depth < 0:
        return "<truncated>"
    if value is None or isinstance(value, (int, float, bool)):
        return value
    if isinstance(value, str):
        if len(value) <= MAX_RAW_TEXT_CHARS:
            return value
        return value[:MAX_RAW_TEXT_CHARS] + "\n<truncated>"
    if isinstance(value, list):
        items = [truncate_value(item, max_depth - 1) for item in value[:MAX_RAW_LIST_ITEMS]]
        if len(value) > MAX_RAW_LIST_ITEMS:
            items.append({"truncated_items": len(value) - MAX_RAW_LIST_ITEMS})
        return items
    if isinstance(value, dict):
        output: Dict[str, Any] = {}
        for idx, (key, item) in enumerate(value.items()):
            if idx >= MAX_RAW_DICT_KEYS:
                output["truncated_keys"] = len(value) - MAX_RAW_DICT_KEYS
                break
            output[str(key)] = truncate_value(item, max_depth - 1)
        return output
    return safe_str(value)


def is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool))


def collect_scalar_fields(node: Dict[str, Any], exclude_keys: Optional[set] = None) -> Dict[str, Any]:
    exclude_keys = exclude_keys or set()
    scalars: Dict[str, Any] = {}
    for key, value in node.items():
        if key in exclude_keys:
            continue
        if is_scalar(value):
            scalars[key] = truncate_value(value, max_depth=0)
        elif isinstance(value, dict):
            nested_scalars = {k: v for k, v in value.items() if is_scalar(v)}
            if nested_scalars:
                scalars[key] = truncate_value(nested_scalars, max_depth=1)
    return scalars


def has_list_of_dicts(node: Dict[str, Any]) -> bool:
    for value in node.values():
        if isinstance(value, list) and value and all(isinstance(item, dict) for item in value[: min(len(value), 5)]):
            return True
    return False


def candidate_score(node: Dict[str, Any]) -> int:
    keys = {str(key).lower() for key in node.keys()}
    scalar_count = sum(1 for value in node.values() if is_scalar(value))
    score = scalar_count
    score += len(keys.intersection(SIGNAL_KEYS)) * 2
    if "url" in keys or "uri" in keys or "path" in keys:
        score += 2
    if "status" in keys or "riskcode" in keys or "port" in keys or "portid" in keys:
        score += 1
    return score


def make_json_path(parent_path: str, key: Any, is_index: bool) -> str:
    if is_index:
        return f"{parent_path}[{key}]"
    if parent_path == "$":
        return f"$.{key}"
    return f"{parent_path}.{key}"


def build_candidate_from_dict(
    *,
    tool_name: str,
    record_id: str,
    json_path: str,
    parent_path: str,
    record_type_hint: str,
    parent_key: Optional[str],
    node: Dict[str, Any],
    ancestor_context: List[Dict[str, Any]],
    parent_scalar_context: Dict[str, Any],
    default_port: int,
    max_list_items: int,
) -> Dict[str, Any]:
    sibling_keys = sorted([str(key) for key in node.keys()])[:50]
    return {
        "record_id": record_id,
        "tool_name": tool_name,
        "json_path": json_path,
        "parent_path": parent_path,
        "record_type_hint": record_type_hint,
        "parent_key": parent_key,
        "default_port": str(default_port),
        "local_context": {
            "sibling_keys": sibling_keys,
            "parent_scalar_context": truncate_value(parent_scalar_context, max_depth=1),
            "ancestor_context": truncate_value(ancestor_context, max_depth=2),
        },
        "record_data": truncate_value(node, max_depth=3),
    }


def build_candidate_from_text_line(
    *,
    tool_name: str,
    record_id: str,
    line_index: int,
    line_text: str,
    nearby_lines: List[str],
    default_port: int,
) -> Dict[str, Any]:
    return {
        "record_id": record_id,
        "tool_name": tool_name,
        "json_path": f"$[line:{line_index}]",
        "parent_path": "$",
        "record_type_hint": "text_line",
        "parent_key": None,
        "default_port": str(default_port),
        "local_context": {"nearby_lines": nearby_lines},
        "record_data": {"line": line_text},
    }


def interesting_text_lines(text: str, limit: int = MAX_TEXT_CANDIDATES) -> List[Tuple[int, str]]:
    selected: List[Tuple[int, str]] = []
    lines = safe_str(text).splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped:
            continue
        selected.append((idx, stripped))

    if len(selected) > limit:
        head = selected[: limit // 2]
        tail = selected[-(limit - len(head)) :]
        selected = head + tail

    return selected


def build_record_candidates_from_text(
    *,
    tool_name: str,
    record_id_prefix: str,
    text: str,
    default_port: int,
) -> List[Dict[str, Any]]:
    lines = [line.rstrip() for line in safe_str(text).splitlines()]
    selected = interesting_text_lines(text)
    candidates: List[Dict[str, Any]] = []
    for idx, line in selected:
        nearby: List[str] = []
        for context_idx in range(max(0, idx - 1), min(len(lines), idx + 2)):
            nearby_line = lines[context_idx].strip()
            if nearby_line:
                nearby.append(nearby_line)
        candidates.append(
            build_candidate_from_text_line(
                tool_name=tool_name,
                record_id=f"{record_id_prefix}_{idx:05d}",
                line_index=idx,
                line_text=line,
                nearby_lines=nearby,
                default_port=default_port,
            )
        )
    return candidates


def slice_json_records(
    tool_name: str,
    raw_output: Any,
    default_port: int,
    max_record_ancestors: int,
    max_list_items: int,
) -> List[Dict[str, Any]]:
    candidates: List[Dict[str, Any]] = []
    seen_paths = set()
    counter = 0

    def next_record_id() -> str:
        nonlocal counter
        record_id = f"rec_{tool_name}_{counter:05d}"
        counter += 1
        return record_id

    def ancestor_summary(ancestors: List[Tuple[str, Optional[str], Dict[str, Any]]]) -> List[Dict[str, Any]]:
        records = []
        for path, key, node in ancestors[-max_record_ancestors:]:
            if not isinstance(node, dict):
                continue
            records.append(
                {
                    "path": path,
                    "key": key,
                    "scalar_fields": collect_scalar_fields(node),
                }
            )
        return records

    def walk(
        node: Any,
        path: str,
        parent_path: str,
        parent_kind: Optional[str],
        parent_key: Optional[str],
        ancestors: List[Tuple[str, Optional[str], Dict[str, Any]]],
        parent_container: Any,
    ) -> None:
        if isinstance(node, dict):
            should_emit = False
            hint = "dict_object"

            if parent_kind == "list":
                hint = "list_item_object"
                if not has_list_of_dicts(node) or candidate_score(node) >= 4:
                    should_emit = True
            elif parent_kind == "dict":
                hint = "dict_field_object"
                if not has_list_of_dicts(node) and candidate_score(node) >= 5:
                    should_emit = True

            if should_emit and path not in seen_paths:
                seen_paths.add(path)
                parent_scalar = {}
                if isinstance(parent_container, dict):
                    parent_scalar = collect_scalar_fields(parent_container, exclude_keys={parent_key} if parent_key else set())
                candidates.append(
                    build_candidate_from_dict(
                        tool_name=tool_name,
                        record_id=next_record_id(),
                        json_path=path,
                        parent_path=parent_path,
                        record_type_hint=hint,
                        parent_key=parent_key,
                        node=node,
                        ancestor_context=ancestor_summary(ancestors),
                        parent_scalar_context=parent_scalar,
                        default_port=default_port,
                        max_list_items=max_list_items,
                    )
                )

            next_ancestors = ancestors + [(path, parent_key, node)]
            for key, value in node.items():
                child_path = make_json_path(path, key, False)
                walk(value, child_path, path, "dict", str(key), next_ancestors, node)
        elif isinstance(node, list):
            if node and all(not isinstance(item, (dict, list)) for item in node[: min(len(node), max_list_items)]):
                if path not in seen_paths:
                    seen_paths.add(path)
                    selected = [item for item in node[:max_list_items]]
                    candidates.append(
                        {
                            "record_id": next_record_id(),
                            "tool_name": tool_name,
                            "json_path": path,
                            "parent_path": parent_path,
                            "record_type_hint": "list_scalar_group",
                            "parent_key": parent_key,
                            "default_port": str(default_port),
                            "local_context": {
                                "ancestor_context": ancestor_summary(ancestors),
                                "parent_scalar_context": collect_scalar_fields(parent_container) if isinstance(parent_container, dict) else {},
                            },
                            "record_data": {"items": selected, "item_count": len(node)},
                        }
                    )
                return

            for index, item in enumerate(node):
                child_path = make_json_path(path, index, True)
                walk(item, child_path, path, "list", str(index), ancestors, node)

    if isinstance(raw_output, str):
        candidates.extend(
            build_record_candidates_from_text(
                tool_name=tool_name,
                record_id_prefix=f"rec_{tool_name}",
                text=raw_output,
                default_port=default_port,
            )
        )
        return candidates

    if isinstance(raw_output, (dict, list)):
        walk(raw_output, "$", "", None, None, [], None)

    if not candidates and isinstance(raw_output, dict):
        candidates.append(
            {
                "record_id": next_record_id(),
                "tool_name": tool_name,
                "json_path": "$",
                "parent_path": "",
                "record_type_hint": "root_object",
                "parent_key": None,
                "default_port": str(default_port),
                "local_context": {"ancestor_context": [], "parent_scalar_context": {}, "sibling_keys": list(raw_output.keys())[:50]},
                "record_data": truncate_value(raw_output, max_depth=3),
            }
        )
    return candidates


def build_record_card(
    record_candidate: Dict[str, Any], tool_name: str, target_ip: str, default_port: int
) -> str:
    lines = [
        "[RECORD]",
        f"tool={tool_name}",
        f"record_id={record_candidate['record_id']}",
        f"json_path={record_candidate['json_path']}",
        f"parent_path={record_candidate['parent_path']}",
        f"record_type={record_candidate['record_type_hint']}",
        "",
        "[DEFAULTS]",
        f"target_ip={target_ip}",
        f"default_port={default_port}",
        "[/DEFAULTS]",
        "",
    ]

    hints = build_field_hints(record_candidate)
    if hints:
        lines.append("[FIELD_HINTS]")
        lines.extend(hints)
        lines.append("[/FIELD_HINTS]")
        lines.append("")

    lines.append("[FLAT_FIELDS]")
    flat_fields = flatten_fields(record_candidate.get("record_data", {}), max_depth=3)
    if not flat_fields:
        flat_fields = ["no_fields=true"]
    lines.extend(flat_fields[:40])
    lines.append("[/FLAT_FIELDS]")
    lines.append("")

    lines.append("[LOCAL_CONTEXT]")
    local_context = record_candidate.get("local_context", {})
    local_lines = flatten_fields(local_context, max_depth=2)[:12]
    if not local_lines:
        local_lines = ["no_local_context=true"]
    lines.extend(local_lines)
    lines.append("[/LOCAL_CONTEXT]")
    lines.append("[/RECORD]")
    return "\n".join(lines)


def flatten_fields(value: Any, prefix: str = "", depth: int = 0, max_depth: int = 3) -> List[str]:
    if depth > max_depth:
        return [f"{prefix}=<truncated>"] if prefix else []

    lines: List[str] = []
    if isinstance(value, dict):
        for key, item in value.items():
            next_prefix = f"{prefix}.{key}" if prefix else str(key)
            lines.extend(flatten_fields(item, next_prefix, depth + 1, max_depth))
    elif isinstance(value, list):
        for index, item in enumerate(value[:MAX_RAW_LIST_ITEMS]):
            next_prefix = f"{prefix}[{index}]"
            lines.extend(flatten_fields(item, next_prefix, depth + 1, max_depth))
        if len(value) > MAX_RAW_LIST_ITEMS and prefix:
            lines.append(f"{prefix}[...]=... {len(value) - MAX_RAW_LIST_ITEMS} more items")
    else:
        lines.append(f"{prefix}={safe_str(value)}")
    return lines


def build_field_hints(candidate: Dict[str, Any]) -> List[str]:
    hints: List[str] = []
    flat_lines = flatten_fields(candidate.get("record_data", {}), max_depth=2)
    keys = [line.split("=", 1)[0].lower() for line in flat_lines if "=" in line]
    values = [line.split("=", 1)[1] for line in flat_lines if "=" in line]

    if any("url" in key or "uri" in key for key in keys):
        hints.append("possible_url_fields=" + ",".join(sorted(set(k for k in keys if "url" in k or "uri" in k))[:5]))
    if any("path" in key for key in keys):
        hints.append("possible_path_fields=" + ",".join(sorted(set(k for k in keys if "path" in k))[:5]))
    if any("status" in key for key in keys):
        hints.append("possible_status_fields=" + ",".join(sorted(set(k for k in keys if "status" in k))[:5]))
    if any("port" in key for key in keys):
        hints.append("possible_port_fields=" + ",".join(sorted(set(k for k in keys if "port" in k))[:5]))
    if any("host" in key for key in keys):
        hints.append("possible_host_fields=" + ",".join(sorted(set(k for k in keys if "host" in k))[:5]))
    if any(value.startswith("http://") or value.startswith("https://") for value in values):
        hints.append("contains_url_values=yes")
    if any(value.isdigit() and 1 <= len(value) <= 5 for value in values):
        hints.append("contains_small_numeric_values=yes")
    return hints


def build_record_normalization_gbnf() -> str:
    return r"""
root ::= no-evidence | evidence-block

no-evidence ::= "NO_EVIDENCE"

evidence-block ::= "[EVIDENCE]" nl
                   "tool=" tool-value nl
                   "kind=" kind-value nl
                   "ip=" ip-value nl
                   "port=" port-value nl
                   "protocol=" protocol-value nl
                   "asset_key=" asset-key-value nl
                   "path=" path-value nl
                   "scope=" scope-value nl
                   "title=" short-text nl
                   "summary=" summary-text nl
                   "severity_hint=" severity-value nl
                   "[/EVIDENCE]"

kind-value ::= "service" | "endpoint" | "finding"
protocol-value ::= "tcp" | "udp" | "http" | "https" | "unknown"
scope-value ::= "port" | "path"
severity-value ::= "info" | "low" | "medium" | "high" | "unknown"

tool-value ::= tool-char+
ip-value ::= ip-char+
port-value ::= digit | nonzero-digit digit | nonzero-digit digit digit | nonzero-digit digit digit digit | nonzero-digit digit digit digit digit
asset-key-value ::= "service" | normalized-path
path-value ::= | normalized-path
normalized-path ::= "/" path-char*

short-text ::= text-char text-tail*
summary-text ::= text-char text-tail*
text-tail ::= text-char | " "

nl ::= "\n" | "\r\n"

digit ::= [0-9]
nonzero-digit ::= [1-9]

tool-char ::= [A-Za-z0-9_.-]
ip-char ::= [A-Za-z0-9:.-]
path-char ::= [A-Za-z0-9._~!$&'()*+,;=:@/-]
text-char ::= [A-Za-z0-9.,:;_()/+#-]
"""


def parse_record_gbnf_output(text: str) -> Dict[str, Any]:
    raw = safe_str(text)
    if not raw:
        return {"status": "empty"}
    if raw == "NO_EVIDENCE":
        return {"status": "no_evidence"}

    start = raw.find("[EVIDENCE]")
    if start == -1:
        return {"status": "unparsed", "raw_text": text}
    start += len("[EVIDENCE]")
    end = raw.find("[/EVIDENCE]", start)
    if end == -1:
        end = len(raw)

    body = raw[start:end].strip()
    parsed: Dict[str, Any] = {"status": "item"}
    for line in body.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        parsed[key.strip()] = value.strip()
    return parsed


def extract_json_candidate(text: str) -> Optional[str]:
    raw = safe_str(text).strip()
    if not raw:
        return None
    if raw.startswith("{") and raw.endswith("}"):
        return raw

    start = raw.find("{")
    if start == -1:
        return None

    depth = 0
    for idx in range(start, len(raw)):
        char = raw[idx]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return raw[start : idx + 1]
    return None


def llm_chat_json(
    client: OpenAI,
    model: str,
    system_prompt: str,
    payload: Dict[str, Any],
    max_tokens: int,
    temperature: float,
) -> Tuple[Optional[Dict[str, Any]], str]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(payload, ensure_ascii=False, separators=(",", ":"))},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            extra_body={"chat_template_kwargs": {"enable_thinking": False}},
        )
        text = safe_str(response.choices[0].message.content)
    except Exception as exc:
        return None, f"[llm_error] {exc}"

    candidate = extract_json_candidate(text)
    if not candidate:
        return None, text
    try:
        parsed = json.loads(candidate)
        if isinstance(parsed, dict):
            return parsed, text
        return None, text
    except Exception:
        return None, text


def llm_chat_gbnf(
    client: OpenAI,
    model: str,
    system_prompt: str,
    user_content: str,
    max_tokens: int,
    temperature: float,
) -> Tuple[Dict[str, Any], str]:
    try:
        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
            max_tokens=max_tokens,
            temperature=temperature,
            top_p=1.0,
            presence_penalty=2.0,
            extra_body={
                "top_k": 20,
                "chat_template_kwargs": {"enable_thinking": False},
                "grammar": build_record_normalization_gbnf(),
            },
        )
        text = safe_str(response.choices[0].message.content)
    except Exception as exc:
        return {"status": "error", "error": f"[llm_error] {exc}"}, f"[llm_error] {exc}"
    return parse_record_gbnf_output(text), text


def repair_json_with_llm(client: OpenAI, model: str, bad_text: str, max_tokens: int) -> Optional[Dict[str, Any]]:
    repaired, _ = llm_chat_json(
        client=client,
        model=model,
        system_prompt="You are a JSON repair engine. Repair the provided content into valid JSON only.",
        payload={"broken_json": bad_text},
        max_tokens=max_tokens,
        temperature=0.0,
    )
    return repaired


def extract_candidate_attributes(record_candidate: Dict[str, Any]) -> Dict[str, Any]:
    record_data = record_candidate.get("record_data")
    if isinstance(record_data, dict):
        return collect_scalar_fields(record_data)
    if isinstance(record_data, list):
        return {"items": truncate_value(record_data, max_depth=1)}
    return {}


def normalize_severity(value: Any) -> str:
    raw = safe_str(value).lower()
    if not raw:
        return "Unknown"
    if raw in ("4", "critical"):
        return "Critical"
    if raw in ("3", "high"):
        return "High"
    if raw in ("2", "medium"):
        return "Medium"
    if raw in ("1", "low"):
        return "Low"
    if raw in ("0", "informational", "info"):
        return "Informational"
    if "critical" in raw:
        return "Critical"
    if "high" in raw:
        return "High"
    if "medium" in raw:
        return "Medium"
    if "low" in raw:
        return "Low"
    if "info" in raw:
        return "Informational"
    return "Unknown"


def snake_identifier(value: Any, fallback: str = "item", max_length: int = 64) -> str:
    raw = safe_str(value).lower()
    chars: List[str] = []
    previous_sep = False
    for char in raw:
        if char.isalnum():
            chars.append(char)
            previous_sep = False
        elif not previous_sep:
            chars.append("_")
            previous_sep = True
    identifier = "".join(chars).strip("_") or fallback
    if identifier[0].isdigit():
        identifier = f"{fallback}_{identifier}"
    return identifier[:max_length] or fallback


def slugify_finding_key(value: Any, fallback: str = "finding") -> str:
    return snake_identifier(value, fallback=fallback, max_length=48)


def make_finding_key(finding: Dict[str, Any], existing: Optional[set] = None) -> str:
    existing = existing or set()
    parts = [
        safe_str(finding.get("vulnerability")),
        safe_str(finding.get("path")),
        safe_str(finding.get("severity")),
    ]
    key = slugify_finding_key("_".join(part for part in parts if part), fallback="finding")
    if key not in existing:
        return key
    digest_src = json.dumps(
        {
            "path": finding.get("path"),
            "vulnerability": finding.get("vulnerability"),
            "severity": finding.get("severity"),
            "tools": finding.get("tools", {}),
            "affected_targets": finding.get("affected_targets", []),
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode("utf-8")
    suffix = hashlib.sha1(digest_src).hexdigest()[:6]
    candidate = f"{key}_{suffix}"
    if candidate not in existing:
        return candidate
    idx = 2
    while f"{candidate}_{idx}" in existing:
        idx += 1
    return f"{candidate}_{idx}"


def normalize_path(value: Any) -> str:
    raw = safe_str(value)
    if not raw:
        return "service"
    if raw.lower() in {"global", "root", "port", "service"}:
        return "service" if raw.lower() != "service" else "service"
    if raw.startswith("http://") or raw.startswith("https://"):
        parsed = urlparse(raw)
        raw = parsed.path or "/"
    raw = raw.split("?", 1)[0].split("#", 1)[0].strip()
    if not raw:
        return "/"
    if not raw.startswith("/"):
        raw = "/" + raw
    if len(raw) > 1 and raw.endswith("/"):
        raw = raw.rstrip("/")
    return raw


def sanitize_final_path(value: Any, fallback: str = "service") -> str:
    raw = safe_str(value)
    if not raw or raw == "global":
        return fallback
    stripped = raw.strip()
    if stripped.startswith("http://") or stripped.startswith("https://"):
        parsed = urlparse(stripped)
        raw = parsed.path or "/"
    else:
        candidate = stripped.lstrip("/")
        host_candidate = candidate
        if ":" in host_candidate and host_candidate.count(":") == 1 and host_candidate.rsplit(":", 1)[1].isdigit():
            host_candidate = host_candidate.rsplit(":", 1)[0]
        if host_candidate and "/" not in candidate:
            try:
                ip_address(host_candidate)
                return fallback
            except ValueError:
                pass
            if "." in host_candidate and all(char.isalnum() or char in ".-" for char in host_candidate):
                return fallback
    return normalize_path(raw)


def sanitize_tool_summary(value: Any, fallback: str = "") -> str:
    if isinstance(value, (dict, list)):
        raw = json.dumps(truncate_value(value, max_depth=3), ensure_ascii=False, separators=(",", ":"))
    else:
        raw = safe_str(value)
    return raw or fallback


def build_service_context_from_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    context: Dict[str, Any] = {}
    if not isinstance(attrs, dict):
        return context

    state = attrs.get("state")
    if isinstance(state, dict):
        context["state"] = safe_str(state.get("@state") or state.get("state")) or None
    else:
        context["state"] = safe_str(state or attrs.get("@state")) or None

    service = attrs.get("service")
    if isinstance(service, dict):
        context["service_name"] = safe_str(service.get("@name") or service.get("name")) or None
        context["product"] = safe_str(service.get("@product") or service.get("product")) or None
        context["version"] = safe_str(service.get("@version") or service.get("version")) or None
        context["tunnel"] = safe_str(service.get("@tunnel") or service.get("tunnel")) or None
        context["cpe"] = safe_str(service.get("cpe") or service.get("@cpe")) or None
    else:
        context["service_name"] = safe_str(attrs.get("service_name") or attrs.get("@name")) or None
        context["product"] = safe_str(attrs.get("product") or attrs.get("@product")) or None
        context["version"] = safe_str(attrs.get("version") or attrs.get("@version")) or None
        context["tunnel"] = safe_str(attrs.get("tunnel") or attrs.get("@tunnel")) or None
        context["cpe"] = safe_str(attrs.get("cpe") or attrs.get("@cpe")) or None

    return context


def validate_evidence_object(
    raw: Dict[str, Any],
    *,
    record_candidate: Dict[str, Any],
    target_ip: str,
    tool_name: str,
    default_port: str,
    evidence_index: int,
) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None

    kind = safe_str(raw.get("kind"))
    if kind not in ALLOWED_KINDS:
        return None

    ip = safe_str(raw.get("ip")) or target_ip
    port = safe_str(raw.get("port")) or default_port
    protocol = safe_str(raw.get("protocol")) or "unknown"
    if protocol not in ("tcp", "udp", "http", "https", "unknown"):
        protocol = "unknown"

    asset_key_raw = raw.get("asset_key")
    path_raw = raw.get("path")
    if kind == "service":
        asset_key = "service"
        path = "service"
        scope = "port"
    else:
        candidate_path = path_raw or asset_key_raw
        path = sanitize_final_path(candidate_path, fallback="service")
        asset_key = "service" if path == "service" else path
        scope = "path" if path != "service" else "port"

    title = safe_str(raw.get("title"))[:120]
    if not title:
        title = f"{tool_name} {kind}"
    severity_hint = normalize_severity(raw.get("severity_hint"))
    summary = safe_str(raw.get("summary")) or title
    description = safe_str(raw.get("description")) or summary

    attributes = extract_candidate_attributes(record_candidate)
    raw_excerpt = truncate_value(record_candidate.get("record_data"), max_depth=2)

    return {
        "evidence_id": f"ev_{tool_name}_{record_candidate['record_id']}_{evidence_index:02d}",
        "tool": tool_name,
        "kind": kind,
        "ip": ip,
        "port": port,
        "protocol": protocol,
        "asset_key": asset_key,
        "path": path,
        "scope": scope,
        "title": title,
        "severity_hint": severity_hint,
        "summary": summary,
        "description": description,
        "attributes": attributes,
        "raw_excerpt": raw_excerpt,
        "source_ref": {
            "tool_name": tool_name,
            "origin_type": "record_candidate",
            "record_id": record_candidate["record_id"],
            "json_path": record_candidate["json_path"],
        },
    }


def is_aggregate_root_candidate(record_candidate: Dict[str, Any]) -> bool:
    json_path = safe_str(record_candidate.get("json_path"))
    parent_path = safe_str(record_candidate.get("parent_path"))
    record_type = safe_str(record_candidate.get("record_type_hint"))
    record_data = record_candidate.get("record_data", {})
    if json_path in ("$", "$.nmaprun"):
        return True
    if parent_path not in ("", "$") or record_type not in ("root_object", "dict_field_object"):
        return False
    if not isinstance(record_data, dict):
        return False
    nested_count = sum(1 for value in record_data.values() if isinstance(value, (dict, list)))
    scalar_keys = len(record_data.keys())
    return scalar_keys >= 5 and nested_count >= 2


def post_validate_evidence_object(
    evidence: Dict[str, Any], record_candidate: Dict[str, Any], target_host: str, target_ip: str
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    item = deepcopy(evidence)
    corrections: List[str] = []

    canonical_ip = canonicalize_target_identifier(item.get("ip"), target_host, target_ip)
    if canonical_ip != item.get("ip"):
        corrections.append("canonicalize_ip")
        item["ip"] = canonical_ip

    if is_aggregate_root_candidate(record_candidate):
        return None, {
            "status": "filtered_aggregate_root",
            "filter_reason": "aggregate_root",
            "corrections": corrections,
            "original_evidence_id": evidence.get("evidence_id"),
            "title": evidence.get("title"),
        }

    if (
        item.get("asset_key") == "service"
        or item.get("kind") == "service"
        or item.get("scope") == "port"
    ):
        if item.get("asset_key") != "service":
            corrections.append("force_service_asset_key")
        if item.get("path") != "service":
            corrections.append("force_service_path")
        item["asset_key"] = "service"
        item["path"] = "service"
        item["scope"] = "port"
    else:
        asset_key = sanitize_final_path(item.get("asset_key") or item.get("path"))
        path = sanitize_final_path(item.get("path") or item.get("asset_key"))
        if asset_key != item.get("asset_key"):
            corrections.append("normalize_asset_key")
        if path != item.get("path"):
            corrections.append("normalize_path")
        item["asset_key"] = asset_key
        item["path"] = path
        item["scope"] = "path"
        if item["asset_key"] != item["path"]:
            corrections.append("align_asset_key_to_path")
            item["asset_key"] = item["path"]

    return item, {
        "status": "corrected" if corrections else "passed",
        "corrections": corrections,
        "evidence_id": item.get("evidence_id"),
        "title": item.get("title"),
    }


def normalize_record_with_llm(
    client: OpenAI,
    config: "RuntimeConfig",
    tool_name: str,
    record_candidate: Dict[str, Any],
    target_host: str,
    target_ip: str,
    default_port: int,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    record_card = build_record_card(record_candidate, tool_name, target_ip, default_port)
    attempts: List[Dict[str, Any]] = []
    post_validation_log: List[Dict[str, Any]] = []

    for attempt in range(config.max_retries + 1):
        parsed, text = llm_chat_gbnf(
            client=client,
            model=config.model,
            system_prompt=PROMPT_RECORD_NORMALIZATION,
            user_content=record_card,
            max_tokens=config.normalize_max_tokens,
            temperature=config.temperature,
        )
        attempts.append({"attempt": attempt, "raw_text": text, "parsed": parsed})

        status = parsed.get("status")
        if status == "no_evidence":
            return [], {
                "record_card": record_card,
                "attempts": attempts,
                "post_validation": [{"status": "model_no_evidence"}],
            }
        if status != "item":
            continue

        clean = validate_evidence_object(
            parsed,
            record_candidate=record_candidate,
            target_ip=target_ip,
            tool_name=tool_name,
            default_port=str(default_port),
            evidence_index=0,
        )
        if clean:
            post_clean, post_meta = post_validate_evidence_object(clean, record_candidate, target_host, target_ip)
            post_validation_log.append(post_meta)
            if post_clean:
                return [post_clean], {
                    "record_card": record_card,
                    "attempts": attempts,
                    "post_validation": post_validation_log,
                }
            return [], {
                "record_card": record_card,
                "attempts": attempts,
                "post_validation": post_validation_log,
            }

    return [], {"record_card": record_card, "attempts": attempts, "post_validation": post_validation_log}


def collect_all_evidence_recordwise(
    target: Dict[str, Any],
    client: OpenAI,
    config: "RuntimeConfig",
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Dict[str, Any]], str, str, Dict[str, Any]]:
    tool_results = target.get("tool_results") or {}
    target_host_value = target_host(target)
    target_ip_value = target_ip(target)
    default_port = int(target.get("port") or 80)
    all_record_candidates: List[Dict[str, Any]] = []
    evidence_list: List[Dict[str, Any]] = []
    normalize_debug: Dict[str, Any] = {}

    for tool_name, tool_result in tool_results.items():
        if not isinstance(tool_result, dict):
            normalize_debug[tool_name] = {"record_count": 0, "evidence_count": 0, "skipped": True}
            continue

        structured_sources: List[Tuple[str, Any]] = []
        text_sources: List[Tuple[str, Any]] = []
        summary = tool_result.get("summary")
        raw_outputs = tool_result.get("raw_outputs") or {}
        if isinstance(raw_outputs, dict):
            for key, payload in raw_outputs.items():
                if not isinstance(payload, dict):
                    continue
                content = payload.get("content")
                fmt = safe_str(payload.get("format"))
                if content is None:
                    continue
                if fmt in {"json", "jsonl"}:
                    structured_sources.append((f"raw:{key}:{fmt}", content))
                elif fmt == "text":
                    text_sources.append((f"raw:{key}:{fmt}", content))

        sources: List[Tuple[str, Any]] = structured_sources or text_sources
        source_mode = "raw_structured" if structured_sources else "raw_text" if text_sources else "summary_fallback"

        record_candidates: List[Dict[str, Any]] = []
        seen_paths = set()
        for source_key, source_value in sources:
            candidates = slice_json_records(
                tool_name=tool_name,
                raw_output=source_value,
                default_port=default_port,
                max_record_ancestors=config.max_record_ancestors,
                max_list_items=config.max_list_items,
            )
            for candidate in candidates:
                candidate.setdefault("source_key", source_key)
                if candidate["json_path"] in seen_paths:
                    continue
                seen_paths.add(candidate["json_path"])
                record_candidates.append(candidate)

        if not record_candidates and summary is not None:
            record_candidates = slice_json_records(
                tool_name=tool_name,
                raw_output=summary,
                default_port=default_port,
                max_record_ancestors=config.max_record_ancestors,
                max_list_items=config.max_list_items,
            )
            source_mode = "summary_fallback"
            for candidate in record_candidates:
                candidate.setdefault("source_key", "summary:fallback")

        all_record_candidates.extend(record_candidates)
        tool_debug = {
            "record_count": len(record_candidates),
            "evidence_count": 0,
            "source_mode": source_mode,
            "records": {},
        }
        print(f"[slice] {tool_name}: {len(record_candidates)} record candidates")

        for candidate in record_candidates:
            normalized, debug_info = normalize_record_with_llm(
                client=client,
                config=config,
                tool_name=tool_name,
                record_candidate=candidate,
                target_host=target_host_value,
                target_ip=target_ip_value,
                default_port=default_port,
            )
            evidence_list.extend(normalized)
            tool_debug["evidence_count"] += len(normalized)
            if config.save_debug:
                tool_debug["records"][candidate["record_id"]] = {
                    "candidate": candidate,
                    "result": normalized,
                    "debug": debug_info,
                }

        normalize_debug[tool_name] = tool_debug

    service_contexts = build_service_contexts_from_evidence(evidence_list, target_ip_value)
    return evidence_list, all_record_candidates, service_contexts, target_host_value, target_ip_value, normalize_debug


def build_service_contexts_from_evidence(
    evidence_list: List[Dict[str, Any]], fallback_ip: str
) -> Dict[str, Dict[str, Any]]:
    contexts: Dict[str, Dict[str, Any]] = {}
    for evidence in evidence_list:
        if evidence.get("kind") != "service":
            continue
        port = safe_str(evidence.get("port"))
        if not port:
            continue
        context = contexts.setdefault(
            port,
            {
                "ip": safe_str(evidence.get("ip")) or fallback_ip,
                "port": port,
                "protocol": safe_str(evidence.get("protocol")) or "tcp",
                "state": None,
                "service_name": None,
                "product": None,
                "version": None,
                "tunnel": None,
                "cpe": None,
                "source_tool": evidence.get("tool"),
            },
        )
        attrs = evidence.get("attributes", {})
        if not isinstance(attrs, dict):
            attrs = {}
        service_ctx = build_service_context_from_attributes(attrs)
        context["ip"] = context["ip"] or safe_str(evidence.get("ip")) or fallback_ip
        context["protocol"] = context["protocol"] or safe_str(evidence.get("protocol")) or "tcp"
        context["state"] = context["state"] or service_ctx.get("state") or None
        context["service_name"] = context["service_name"] or service_ctx.get("service_name") or None
        context["product"] = context["product"] or service_ctx.get("product") or None
        context["version"] = context["version"] or service_ctx.get("version") or None
        context["tunnel"] = context["tunnel"] or service_ctx.get("tunnel") or None
        context["cpe"] = context["cpe"] or service_ctx.get("cpe") or None
    return contexts


def build_cluster_id(ip: str, port: str, asset_key: str) -> str:
    clean_asset = snake_identifier(asset_key, fallback="service", max_length=64)
    return f"cl_{ip}_{port}_{clean_asset}"


def build_asset_clusters(
    evidence_list: List[Dict[str, Any]], service_contexts: Dict[str, Dict[str, Any]]
) -> List[Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], List[Dict[str, Any]]] = defaultdict(list)
    service_only: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)

    for evidence in evidence_list:
        port = safe_str(evidence.get("port")) or "unknown"
        ip = safe_str(evidence.get("ip")) or "unknown"
        if evidence.get("kind") in ("endpoint", "finding"):
            asset_key = safe_str(evidence.get("asset_key")) or "service"
            grouped[(ip, port, asset_key)].append(evidence)
        else:
            service_only[(ip, port)].append(evidence)

    clusters: List[Dict[str, Any]] = []
    seen_global = set()

    for (ip, port, asset_key), items in grouped.items():
        tools = sorted({item["tool"] for item in items})
        clusters.append(
            {
                "cluster_id": build_cluster_id(ip, port, asset_key),
                "ip": ip,
                "port": port,
                "protocol": service_contexts.get(port, {}).get("protocol", "tcp"),
                "asset_key": asset_key,
                "asset_type": "path" if asset_key != "service" else "global",
                "cluster_scope": "path" if asset_key != "service" else "global",
                "service_context": deepcopy(service_contexts.get(port, {})),
                "evidence_list": [
                    {
                        "evidence_id": item["evidence_id"],
                        "tool": item["tool"],
                        "kind": item["kind"],
                        "path": item.get("path"),
                        "summary": item["summary"],
                        "description": item["description"],
                        "severity_hint": item["severity_hint"],
                        "attributes": item.get("attributes", {}),
                        "raw_excerpt": item.get("raw_excerpt", {}),
                    }
                    for item in items
                ],
                "cluster_stats": {
                    "evidence_count": len(items),
                    "tool_count": len(tools),
                    "tools": tools,
                },
            }
        )
        seen_global.add((ip, port))

    for (ip, port), items in service_only.items():
        if (ip, port) in seen_global:
            continue
        tools = sorted({item["tool"] for item in items})
        clusters.append(
            {
                "cluster_id": build_cluster_id(ip, port, "service"),
                "ip": ip,
                "port": port,
                "protocol": service_contexts.get(port, {}).get("protocol", "tcp"),
                "asset_key": "service",
                "asset_type": "service",
                "cluster_scope": "service",
                "service_context": deepcopy(service_contexts.get(port, {})),
                "evidence_list": [
                    {
                        "evidence_id": item["evidence_id"],
                        "tool": item["tool"],
                        "kind": item["kind"],
                        "path": item.get("path"),
                        "summary": item["summary"],
                        "description": item["description"],
                        "severity_hint": item["severity_hint"],
                        "attributes": item.get("attributes", {}),
                        "raw_excerpt": item.get("raw_excerpt", {}),
                    }
                    for item in items
                ],
                "cluster_stats": {
                    "evidence_count": len(items),
                    "tool_count": len(tools),
                    "tools": tools,
                },
            }
        )

    clusters.sort(
        key=lambda item: (
            item["ip"],
            int(item["port"]) if safe_str(item["port"]).isdigit() else 99999,
            item["asset_key"],
        )
    )
    return clusters


def trim_service_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not context:
        return {}
    return {
        "service_name": context.get("service_name"),
        "product": context.get("product"),
        "version": context.get("version"),
        "tunnel": context.get("tunnel"),
        "state": context.get("state"),
        "cpe": context.get("cpe"),
        "source_tool": context.get("source_tool"),
    }


def build_cluster_payload(cluster: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "task": "integrate_security_evidence",
        "ip": cluster["ip"],
        "port": cluster["port"],
        "asset_key": cluster["asset_key"],
        "asset_type": cluster["asset_type"],
        "service_context": trim_service_context(cluster.get("service_context", {})),
        "evidence_list": cluster["evidence_list"],
        "output_contract": {
            "format": "json_only",
            "allowed_severity": ALLOWED_SEVERITIES,
        },
    }


def normalize_affected_targets(value: Any, cluster_asset_key: str) -> List[str]:
    if isinstance(value, list):
        raw_targets = [safe_str(item) for item in value if safe_str(item)]
    elif safe_str(value):
        raw_targets = [safe_str(value)]
    else:
        raw_targets = []

    targets: List[str] = []
    for item in raw_targets:
        normalized = sanitize_final_path(item, fallback="")
        if normalized and normalized != "service":
            targets.append(normalized)

    fallback_target = sanitize_final_path(cluster_asset_key, fallback="service") if cluster_asset_key else ""
    if not targets and fallback_target and fallback_target != "service":
        targets = [fallback_target]

    deduped: List[str] = []
    seen = set()
    for item in targets:
        if item not in seen:
            seen.add(item)
            deduped.append(item)
    return deduped


def validate_finding_object(
    finding: Dict[str, Any], cluster: Optional[Dict[str, Any]] = None, allowed_tools: Optional[set] = None
) -> Optional[Dict[str, Any]]:
    if not isinstance(finding, dict):
        return None

    path = safe_str(finding.get("path"))
    if cluster:
        asset_key = cluster.get("asset_key") or "service"
        if not path or path == "service":
            path = asset_key
        if asset_key != "service":
            path = sanitize_final_path(path, fallback=normalize_path(asset_key))
        else:
            path = "service"
    elif path:
        path = sanitize_final_path(path, fallback="service")
    else:
        path = "service"

    if path != "service" and ("|" in path or path.startswith("/ ")):
        return None

    tools = finding.get("tools", {})
    if not isinstance(tools, dict):
        return None
    description = safe_str(finding.get("description"))
    clean_tools: Dict[str, str] = {}
    for tool_name, summary in tools.items():
        tool_name = safe_str(tool_name)
        if allowed_tools is not None and tool_name not in allowed_tools:
            continue
        clean_summary = sanitize_tool_summary(summary, fallback=description)
        if tool_name and clean_summary:
            clean_tools[tool_name] = clean_summary
    if not clean_tools:
        return None

    vulnerability = safe_str(finding.get("vulnerability"))
    severity = normalize_severity(finding.get("severity"))
    affected_targets = normalize_affected_targets(finding.get("affected_targets"), path)
    if path == "service":
        affected_targets = ["service"]
    if not vulnerability or not description:
        return None
    if path != "service" and (not affected_targets or any(item == "service" for item in affected_targets)):
        affected_targets = [path]
    if path != "service" and len(path) <= 1:
        return None

    return {
        "path": path,
        "tools": clean_tools,
        "description": description,
        "vulnerability": vulnerability,
        "severity": severity,
        "affected_targets": affected_targets or (["service"] if path == "service" else [path]),
    }


def exact_merge_key(finding: Dict[str, Any]) -> Tuple[str, str, str]:
    return (
        safe_str(finding.get("path")),
        safe_str(finding.get("vulnerability")).casefold(),
        safe_str(finding.get("severity")).casefold(),
    )


def merge_tool_summary(existing: Any, incoming: Any) -> str:
    old_text = safe_str(existing)
    new_text = safe_str(incoming)
    if not old_text:
        return new_text
    if not new_text or new_text == old_text:
        return old_text
    if new_text in old_text:
        return old_text
    if old_text in new_text:
        return new_text
    return f"{old_text} | {new_text}"


def merge_exact_finding(base: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = deepcopy(base)

    merged_tools = dict(merged.get("tools") or {})
    for tool_name, summary in (incoming.get("tools") or {}).items():
        tool_key = safe_str(tool_name)
        if not tool_key:
            continue
        merged_tools[tool_key] = merge_tool_summary(merged_tools.get(tool_key), summary)
    merged["tools"] = merged_tools

    if len(safe_str(incoming.get("description"))) > len(safe_str(merged.get("description"))):
        merged["description"] = incoming.get("description")

    targets: List[str] = []
    seen_targets = set()
    for source in (merged.get("affected_targets"), incoming.get("affected_targets")):
        if isinstance(source, list):
            for item in source:
                target = safe_str(item)
                if target and target not in seen_targets:
                    seen_targets.add(target)
                    targets.append(target)
    if targets:
        merged["affected_targets"] = targets

    return merged


def merge_exact_duplicate_findings(findings_map: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    grouped: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    passthrough: List[Dict[str, Any]] = []
    for finding in findings_map.values():
        if not isinstance(finding, dict):
            continue
        key = exact_merge_key(finding)
        if all(key):
            if key in grouped:
                grouped[key] = merge_exact_finding(grouped[key], finding)
            else:
                grouped[key] = deepcopy(finding)
        else:
            passthrough.append(deepcopy(finding))

    merged: Dict[str, Dict[str, Any]] = {}
    for finding in list(grouped.values()) + passthrough:
        key = make_finding_key(finding, existing=set(merged.keys()))
        merged[key] = finding
    return merged


def validate_findings_map(
    findings_map: Dict[str, Any], cluster: Optional[Dict[str, Any]] = None
) -> Dict[str, Dict[str, Any]]:
    if not isinstance(findings_map, dict):
        return {}
    allowed_tools = None
    if cluster is not None:
        allowed_tools = {item["tool"] for item in cluster.get("evidence_list", [])}
    validated: Dict[str, Dict[str, Any]] = {}
    for _, raw_finding in findings_map.items():
        clean = validate_finding_object(raw_finding, cluster=cluster, allowed_tools=allowed_tools)
        if clean:
            key = make_finding_key(clean, existing=set(validated.keys()))
            validated[key] = clean
    return merge_exact_duplicate_findings(validated)


def integrate_cluster_with_llm(
    client: OpenAI, config: "RuntimeConfig", cluster: Dict[str, Any]
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    payload = build_cluster_payload(cluster)
    attempts: List[Dict[str, Any]] = []
    raw_text = ""

    for attempt in range(config.max_retries + 1):
        parsed, text = llm_chat_json(
            client=client,
            model=config.model,
            system_prompt=PROMPT_CLUSTER_INTEGRATION,
            payload=payload,
            max_tokens=config.cluster_max_tokens,
            temperature=config.temperature,
        )
        raw_text = text
        attempts.append({"attempt": attempt, "raw_text": text, "parsed": parsed})
        if parsed is None:
            repaired = repair_json_with_llm(client, config.model, text, config.cluster_max_tokens)
            if repaired is not None:
                parsed = repaired
        validated = validate_findings_map(parsed or {}, cluster=cluster)
        if validated:
            return validated, {"payload": payload, "attempts": attempts}
        if parsed == {}:
            return {}, {"payload": payload, "attempts": attempts}

    repaired = repair_json_with_llm(client, config.model, raw_text, config.cluster_max_tokens)
    validated = validate_findings_map(repaired or {}, cluster=cluster)
    return validated, {"payload": payload, "attempts": attempts, "repaired": repaired}


def build_port_dedup_payload(
    ip: str, port: str, service_context: Dict[str, Any], candidate_findings: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "task": "deduplicate_port_findings",
        "ip": ip,
        "port": port,
        "service_context": trim_service_context(service_context),
        "candidate_findings": candidate_findings,
        "output_contract": {
            "format": "json_only",
            "do_not_create_new_paths": True,
            "do_not_create_new_tools": True,
            "allowed_severity": ALLOWED_SEVERITIES,
        },
    }


def build_relevance_filter_payload(
    ip: str, port: str, service_context: Dict[str, Any], candidate_findings: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "task": "filter_security_findings",
        "ip": ip,
        "port": port,
        "service_context": trim_service_context(service_context),
        "candidate_findings": candidate_findings,
        "output_contract": {
            "format": "json_only",
            "operation": "remove_only",
            "do_not_create_new_paths": True,
            "do_not_create_new_tools": True,
            "allowed_severity": ALLOWED_SEVERITIES,
        },
    }


def dedup_port_findings_with_llm(
    client: OpenAI,
    config: "RuntimeConfig",
    ip: str,
    port: str,
    service_context: Dict[str, Any],
    cluster_results: Dict[str, Dict[str, Dict[str, Any]]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    flattened = {}
    allowed_tools = set()
    counter = 0
    for findings in cluster_results.values():
        for finding in findings.values():
            flattened[f"candidate_{counter}"] = finding
            allowed_tools.update(finding.get("tools", {}).keys())
            counter += 1

    if not flattened:
        return {}, {"payload": None, "attempts": []}
    if len(flattened) == 1:
        only_finding = next(iter(flattened.values()))
        return {make_finding_key(only_finding): only_finding}, {"payload": None, "attempts": []}

    payload = build_port_dedup_payload(ip, port, service_context, flattened)
    attempts: List[Dict[str, Any]] = []

    for attempt in range(config.max_retries + 1):
        parsed, text = llm_chat_json(
            client=client,
            model=config.model,
            system_prompt=PROMPT_PORT_DEDUP,
            payload=payload,
            max_tokens=config.dedup_max_tokens,
            temperature=config.temperature,
        )
        attempts.append({"attempt": attempt, "raw_text": text, "parsed": parsed})
        if parsed is None:
            repaired = repair_json_with_llm(client, config.model, text, config.dedup_max_tokens)
            if repaired is not None:
                parsed = repaired
        validated = {}
        if isinstance(parsed, dict):
            for _, raw_finding in parsed.items():
                clean = validate_finding_object(raw_finding, cluster=None, allowed_tools=allowed_tools)
                if clean:
                    key = make_finding_key(clean, existing=set(validated.keys()))
                    validated[key] = clean
        if validated:
            return merge_exact_duplicate_findings(validated), {"payload": payload, "attempts": attempts}
        if parsed == {}:
            break

    fallback = {}
    for finding in flattened.values():
        fallback[make_finding_key(finding, existing=set(fallback.keys()))] = finding
    return merge_exact_duplicate_findings(fallback), {"payload": payload, "attempts": attempts, "fallback_used": True}


def filter_port_findings_with_llm(
    client: OpenAI,
    config: "RuntimeConfig",
    ip: str,
    port: str,
    service_context: Dict[str, Any],
    candidate_findings: Dict[str, Dict[str, Any]],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    if not candidate_findings:
        return {}, {"payload": None, "attempts": []}

    payload = build_relevance_filter_payload(ip, port, service_context, candidate_findings)
    allowed_tools = set()
    for finding in candidate_findings.values():
        allowed_tools.update(finding.get("tools", {}).keys())

    attempts: List[Dict[str, Any]] = []
    raw_text = ""
    for attempt in range(config.max_retries + 1):
        parsed, text = llm_chat_json(
            client=client,
            model=config.model,
            system_prompt=PROMPT_FINDING_RELEVANCE,
            payload=payload,
            max_tokens=config.relevance_max_tokens,
            temperature=config.temperature,
        )
        raw_text = text
        attempts.append({"attempt": attempt, "raw_text": text, "parsed": parsed})
        if parsed is None:
            repaired = repair_json_with_llm(client, config.model, text, config.relevance_max_tokens)
            if repaired is not None:
                parsed = repaired
        if parsed == {}:
            return {}, {"payload": payload, "attempts": attempts}
        if isinstance(parsed, dict):
            validated: Dict[str, Dict[str, Any]] = {}
            for _, raw_finding in parsed.items():
                clean = validate_finding_object(raw_finding, cluster=None, allowed_tools=allowed_tools)
                if clean:
                    key = make_finding_key(clean, existing=set(validated.keys()))
                    validated[key] = clean
            if validated:
                return merge_exact_duplicate_findings(validated), {"payload": payload, "attempts": attempts}

    repaired = repair_json_with_llm(client, config.model, raw_text, config.relevance_max_tokens)
    if repaired == {}:
        return {}, {"payload": payload, "attempts": attempts, "repaired": repaired}
    if isinstance(repaired, dict):
        validated = {}
        for _, raw_finding in repaired.items():
            clean = validate_finding_object(raw_finding, cluster=None, allowed_tools=allowed_tools)
            if clean:
                key = make_finding_key(clean, existing=set(validated.keys()))
                validated[key] = clean
        if validated:
            return merge_exact_duplicate_findings(validated), {
                "payload": payload,
                "attempts": attempts,
                "repaired": repaired,
            }

    return merge_exact_duplicate_findings(candidate_findings), {
        "payload": payload,
        "attempts": attempts,
        "fallback_used": True,
    }


def group_clusters_by_ip_port(clusters: List[Dict[str, Any]]) -> Dict[Tuple[str, str], List[Dict[str, Any]]]:
    grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
    for cluster in clusters:
        grouped[(cluster["ip"], cluster["port"])].append(cluster)
    return grouped


def canonicalize_target_identifier(value: Any, target_host: str, target_ip: str) -> str:
    raw = safe_str(value)
    if not raw:
        return target_ip
    lowered = raw.lower()
    host = safe_str(target_host).lower()
    if lowered == safe_str(target_ip).lower():
        return target_ip
    if host and (lowered == host or lowered.startswith(host + ":")):
        return target_ip
    if lowered.startswith("http://") or lowered.startswith("https://"):
        parsed = urlparse(raw)
        host_name = safe_str(parsed.hostname).lower()
        if host_name == host:
            return target_ip
    return raw


def canonicalize_final_assets(
    final_assets: Dict[str, Dict[str, Any]], target_host: str, target_ip: str
) -> Dict[str, Dict[str, Any]]:
    canonical: Dict[str, Dict[str, Any]] = defaultdict(dict)
    for raw_ip, port_map in final_assets.items():
        canon_ip = canonicalize_target_identifier(raw_ip, target_host, target_ip)
        for port, findings in port_map.items():
            if port not in canonical[canon_ip]:
                canonical[canon_ip][port] = findings
                continue
            existing = canonical[canon_ip][port]
            if not existing:
                canonical[canon_ip][port] = findings
                continue
            if not findings:
                continue
            merged = dict(existing)
            for finding in findings.values():
                new_key = make_finding_key(finding, existing=set(merged.keys()))
                merged[new_key] = finding
            canonical[canon_ip][port] = merged
    return canonical


def assemble_final_output(
    metadata: Dict[str, Any], config: "RuntimeConfig", final_assets: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    if not config.emit_metadata:
        return {"assets": final_assets}
    output_metadata = deepcopy(metadata)
    output_metadata.setdefault("pipeline", "gemma_chain_v1")
    output_metadata["model"] = config.model
    output_metadata["base_url"] = config.base_url
    return {
        "metadata": output_metadata,
        "assets": final_assets,
    }


def save_json(data: Any, file_path: str) -> None:
    path = Path(file_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def write_debug_files(prefix: str, payloads: Dict[str, Any]) -> None:
    for suffix, data in payloads.items():
        save_json(data, f"{prefix}_{suffix}.json")


@dataclass
class RuntimeConfig:
    input_file: str
    output_file: str
    model: str
    base_url: str
    api_key: str
    max_retries: int
    normalize_max_tokens: int
    cluster_max_tokens: int
    dedup_max_tokens: int
    relevance_max_tokens: int
    temperature: float
    emit_metadata: bool
    save_debug: bool
    debug_prefix: str
    max_record_ancestors: int
    max_list_items: int
    dry_run: bool


def parse_args() -> RuntimeConfig:
    parser = argparse.ArgumentParser(
        description="Gemma chain integration pipeline: record-wise normalization + cluster merge + port dedup."
    )
    parser.add_argument("--input", required=True, help="Path to aggregated scan JSON")
    parser.add_argument("--output", default="reports/final_report.json", help="Path to output JSON")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="OpenAI-compatible model name")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL, help="OpenAI-compatible base URL")
    parser.add_argument("--api-key", default="EMPTY", help="API key for the local endpoint")
    parser.add_argument("--max-retries", type=int, default=1, help="LLM retry count")
    parser.add_argument(
        "--normalize-max-tokens",
        type=int,
        default=800,
        help="max_tokens for record normalization calls",
    )
    parser.add_argument(
        "--cluster-max-tokens",
        type=int,
        default=1200,
        help="max_tokens for cluster integration calls",
    )
    parser.add_argument(
        "--dedup-max-tokens",
        type=int,
        default=1400,
        help="max_tokens for port deduplication calls",
    )
    parser.add_argument(
        "--relevance-max-tokens",
        type=int,
        default=1200,
        help="max_tokens for final LLM relevance filtering calls",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.0,
        help="Sampling temperature for all LLM calls",
    )
    parser.add_argument(
        "--no-metadata",
        action="store_true",
        help="Output only the assets tree without metadata wrapper",
    )
    parser.add_argument(
        "--save-debug",
        action="store_true",
        help="Save sliced records, evidence, clusters, and intermediate outputs",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print a scan summary without calling the LLM",
    )
    parser.add_argument(
        "--debug-prefix",
        default="debug_gemma_chain_v1",
        help="Prefix used for debug JSON files",
    )
    parser.add_argument(
        "--max-record-ancestors",
        type=int,
        default=3,
        help="How many ancestor contexts to attach to each record candidate",
    )
    parser.add_argument(
        "--max-list-items",
        type=int,
        default=8,
        help="How many list items to keep when pruning a record for the LLM",
    )
    args = parser.parse_args()

    return RuntimeConfig(
        input_file=args.input,
        output_file=args.output,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
        max_retries=max(0, args.max_retries),
        normalize_max_tokens=max(256, args.normalize_max_tokens),
        cluster_max_tokens=max(128, args.cluster_max_tokens),
        dedup_max_tokens=max(128, args.dedup_max_tokens),
        relevance_max_tokens=max(128, args.relevance_max_tokens),
        temperature=args.temperature,
        emit_metadata=not args.no_metadata,
        save_debug=args.save_debug,
        debug_prefix=args.debug_prefix,
        max_record_ancestors=max(1, args.max_record_ancestors),
        max_list_items=max(1, args.max_list_items),
        dry_run=args.dry_run,
    )


def extract_targets(bundle: Dict[str, Any]) -> List[Dict[str, Any]]:
    targets = bundle.get("targets")
    if isinstance(targets, list):
        return [item for item in targets if isinstance(item, dict)]

    metadata = bundle.get("metadata") or {}
    tool_results = bundle.get("tool_results") or {}
    if isinstance(tool_results, dict) and tool_results:
        return [
            {
                "id": safe_str(metadata.get("target") or "target"),
                "name": safe_str(metadata.get("target") or "target"),
                "kind": metadata.get("kind"),
                "ip": metadata.get("ip"),
                "host": metadata.get("host"),
                "url": metadata.get("target"),
                "port": metadata.get("port"),
                "tool_results": tool_results,
            }
        ]
    return []


def dry_run_summary(bundle: Dict[str, Any], input_path: str) -> Dict[str, Any]:
    targets = extract_targets(bundle)
    tool_counts: Dict[str, int] = {}
    skipped: Dict[str, int] = {}
    failed: Dict[str, int] = {}
    for target in targets:
        for tool, result in (target.get("tool_results") or {}).items():
            tool_counts[tool] = tool_counts.get(tool, 0) + 1
            if isinstance(result, dict) and result.get("skipped"):
                skipped[tool] = skipped.get(tool, 0) + 1
            if isinstance(result, dict) and result.get("returncode") not in (None, 0):
                failed[tool] = failed.get(tool, 0) + 1
    return {
        "input": input_path,
        "targets": len(targets),
        "tools": tool_counts,
        "skipped": skipped,
        "failed": failed,
    }


def main() -> None:
    args = parse_args()
    start = time.time()
    bundle = load_bundle(args.input_file)
    targets = extract_targets(bundle)

    if args.dry_run:
        print(json.dumps(dry_run_summary(bundle, args.input_file), indent=2, ensure_ascii=False))
        return

    client = build_client(args.base_url, args.api_key)
    llm_errors: Dict[str, str] = {}
    target_debug: Dict[str, Any] = {}
    merged_assets: Dict[str, Dict[str, Any]] = defaultdict(dict)

    for target in targets:
        target_output, raw_error, debug_info = integrate_single_target(client, args, target)
        merge_assets(merged_assets, target_output.get("assets") or {})
        if raw_error:
            llm_errors[safe_str(target.get("id") or target_ip(target))] = raw_error
        if args.save_debug:
            target_debug[safe_str(target.get("id") or target_ip(target))] = debug_info

    metadata = deepcopy(bundle.get("metadata", {}))
    metadata["integration_model"] = args.model
    metadata["integration_shape"] = "assets_by_ip_port"
    metadata["integration_pipeline"] = "gemma_chain_v1"
    metadata["targets_count"] = len(targets)
    if llm_errors:
        metadata["llm_parse_errors"] = llm_errors

    output = assemble_final_output(metadata, args, canonicalize_final_assets(merged_assets, "", ""))
    out_path = Path(args.output_file)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(output, indent=2, ensure_ascii=False), encoding="utf-8")

    if args.save_debug:
        write_debug_files(
            args.debug_prefix,
            {
                "targets": target_debug,
            },
        )

    print(f"[done] wrote {out_path}")
    print(f"[done] elapsed {time.time() - start:.2f}s")


def merge_assets(base: Dict[str, Any], addition: Dict[str, Any]) -> None:
    for ip, port_map in addition.items():
        if not isinstance(port_map, dict):
            continue
        base.setdefault(safe_str(ip), {})
        for port, findings in port_map.items():
            if not isinstance(findings, dict):
                continue
            port_key = safe_str(port)
            existing = base[safe_str(ip)].setdefault(port_key, {})
            for key, finding in sorted(findings.items()):
                new_key = key
                if new_key in existing:
                    new_key = make_finding_key(finding, existing=set(existing.keys()))
                existing[new_key] = finding


def integrate_single_target(
    client: OpenAI, args: RuntimeConfig, target: Dict[str, Any]
) -> Tuple[Dict[str, Any], Optional[str], Dict[str, Any]]:
    runtime = RuntimeConfig(
        input_file=args.input_file,
        output_file=args.output_file,
        model=args.model,
        base_url=args.base_url,
        api_key=args.api_key,
        max_retries=max(0, args.max_retries),
        normalize_max_tokens=max(256, args.normalize_max_tokens),
        cluster_max_tokens=max(128, args.cluster_max_tokens),
        dedup_max_tokens=max(128, args.dedup_max_tokens),
        relevance_max_tokens=max(128, args.relevance_max_tokens),
        temperature=args.temperature,
        emit_metadata=args.emit_metadata,
        save_debug=args.save_debug,
        debug_prefix=args.debug_prefix,
        max_record_ancestors=max(1, args.max_record_ancestors),
        max_list_items=max(1, args.max_list_items),
        dry_run=args.dry_run,
    )

    print(f"[init] gemma model: {runtime.model}")
    print(f"[init] target: {safe_str(target.get('id') or target_ip(target))} -> {target_url(target)}")
    evidence_list, record_candidates, service_contexts, target_host_value, target_ip_value, normalize_debug = (
        collect_all_evidence_recordwise(target, client, runtime)
    )
    print(f"[stage] normalized evidence: {len(evidence_list)}")

    clusters = build_asset_clusters(evidence_list, service_contexts)
    print(f"[stage] built clusters: {len(clusters)}")

    grouped_clusters = group_clusters_by_ip_port(clusters)
    cluster_debug: Dict[str, Any] = {}
    port_debug: Dict[str, Any] = {}
    final_assets: Dict[str, Dict[str, Any]] = defaultdict(dict)

    for (ip, port), port_clusters in grouped_clusters.items():
        print(f"[port] {ip}:{port} -> {len(port_clusters)} clusters")
        cluster_results = {}
        for cluster in port_clusters:
            findings, debug_info = integrate_cluster_with_llm(client, runtime, cluster)
            cluster_results[cluster["cluster_id"]] = findings
            if runtime.save_debug:
                cluster_debug[cluster["cluster_id"]] = {
                    "cluster": cluster,
                    "result": findings,
                    "debug": debug_info,
                }

        deduped, debug_info = dedup_port_findings_with_llm(
            client=client,
            config=runtime,
            ip=ip,
            port=port,
            service_context=deepcopy(service_contexts.get(port, {})),
            cluster_results=cluster_results,
        )
        filtered, relevance_debug = filter_port_findings_with_llm(
            client=client,
            config=runtime,
            ip=ip,
            port=port,
            service_context=deepcopy(service_contexts.get(port, {})),
            candidate_findings=deduped,
        )
        final_assets[ip][port] = filtered
        if runtime.save_debug:
            port_debug[f"{ip}:{port}"] = {
                "cluster_results": cluster_results,
                "deduped": deduped,
                "filtered": filtered,
                "debug": debug_info,
                "relevance_debug": relevance_debug,
            }

    for port, context in service_contexts.items():
        ip = context.get("ip") or target_ip_value
        final_assets.setdefault(ip, {})
        final_assets[ip].setdefault(port, {})

    final_assets = canonicalize_final_assets(final_assets, target_host_value, target_ip_value)
    final_assets = {
        ip: {
            port: final_assets[ip][port]
            for port in sorted(
                final_assets[ip].keys(),
                key=lambda item: int(item) if safe_str(item).isdigit() else 99999,
            )
        }
        for ip in sorted(final_assets.keys())
    }

    target_debug = {}
    if runtime.save_debug:
        target_debug = {
            "records": record_candidates,
            "normalize": normalize_debug,
            "evidence": {
                "target_host": target_host_value,
                "target_ip": target_ip_value,
                "service_contexts": service_contexts,
                "items": evidence_list,
            },
            "clusters": clusters,
            "cluster_results": cluster_debug,
            "port_results": port_debug,
        }

    target_output = {
        "id": safe_str(target.get("id") or target_ip(target)),
        "name": safe_str(target.get("name") or target.get("id") or target_ip(target)),
        "kind": safe_str(target.get("kind") or "unknown"),
        "ip": target_ip_value,
        "host": target_host_value,
        "url": target_url(target),
        "port": str(target.get("port") or target_port(target)),
        "assets": final_assets,
    }
    return target_output, None, target_debug


if __name__ == "__main__":
    main()

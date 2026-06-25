#!/usr/bin/env python3
import argparse
import json
import shutil
import subprocess
import time
from collections import Counter
from ipaddress import ip_address
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener
from urllib.parse import urlparse
from uuid import uuid4

import xmltodict
import yaml


OLD_BASELINE_TOOLS = [
    "nmap",
    "nikto",
    "zaproxy",
    "ffuf",
    "metasploit",
]

DEFAULT_TOOLS = [
    "nmap",
    "nikto",
    "zaproxy",
    "ffuf",
    "metasploit",
    "whatweb",
    "httpx",
    "dirb",
]

OPTIONAL_TOOLS = [
    "gobuster",
    "testssl",
    "sqlmap",
    "nuclei",
    "subfinder",
    "amass",
]

ALL_TOOLS = DEFAULT_TOOLS + [tool for tool in OPTIONAL_TOOLS if tool not in DEFAULT_TOOLS]

TOOL_PROFILES = {
    "default": DEFAULT_TOOLS,
    "old": OLD_BASELINE_TOOLS,
    "all": ALL_TOOLS,
    "optional": OPTIONAL_TOOLS,
}


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = build_opener(NoRedirectHandler)


def load_targets(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    targets = data.get("targets", [])
    if not isinstance(targets, list):
        raise SystemExit("targets file must contain a top-level 'targets' list")
    return targets


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def safe_name(value: str) -> str:
    chars = [ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in value]
    return "".join(chars).strip("_") or "target"


def now_run_id() -> str:
    return time.strftime("%Y%m%d_%H%M%S")


def target_host(target: Dict[str, Any]) -> str:
    return str(target.get("ip") or target.get("host") or "127.0.0.1")


def target_url(target: Dict[str, Any]) -> str:
    url = str(target.get("url") or "").strip()
    if url:
        return url
    host = target_host(target)
    port = int(target.get("port") or 80)
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}:{port}"


def run_command(cmd: List[str], outfile: Path, timeout: int = 900) -> Dict[str, Any]:
    ensure_dir(outfile.parent)
    started = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        content = (proc.stdout or "") + (("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or ""))
        outfile.write_text(content, encoding="utf-8")
        return {
            "command": cmd,
            "returncode": proc.returncode,
            "seconds": round(time.time() - started, 2),
            "output": str(outfile),
        }
    except FileNotFoundError:
        outfile.write_text(f"missing binary: {cmd[0]}\n", encoding="utf-8")
        return {
            "command": cmd,
            "returncode": 127,
            "seconds": round(time.time() - started, 2),
            "output": str(outfile),
            "error": "missing_binary",
        }
    except subprocess.TimeoutExpired:
        outfile.write_text("command timed out\n", encoding="utf-8")
        return {
            "command": cmd,
            "returncode": 124,
            "seconds": round(time.time() - started, 2),
            "output": str(outfile),
            "error": "timeout",
        }


def read_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def read_text(path: Path) -> str:
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def read_jsonl(path: Path) -> List[Any]:
    if not path.exists():
        return []
    records = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except Exception:
            records.append({"raw": line})
    return records


def read_artifact_payload(path: Path) -> Dict[str, Any]:
    payload = file_info(path)
    suffix = path.suffix.lower()
    if not path.exists():
        payload["missing"] = True
        return payload

    if suffix == ".json":
        parsed = read_json(path)
        payload["format"] = "json"
        payload["content"] = parsed if parsed is not None else read_text(path)
        if parsed is None:
            payload["parse_error"] = "invalid_json"
        return payload

    if suffix == ".jsonl":
        payload["format"] = "jsonl"
        payload["content"] = read_jsonl(path)
        return payload

    payload["format"] = "text"
    payload["content"] = read_text(path)
    return payload


def attach_raw_outputs(result: Dict[str, Any]) -> None:
    raw_outputs: Dict[str, Any] = {}

    log_path = result.get("output")
    if isinstance(log_path, str) and log_path:
        raw_outputs["log"] = read_artifact_payload(Path(log_path))

    for key, artifact in (result.get("artifacts") or {}).items():
        path = artifact.get("path") if isinstance(artifact, dict) else artifact
        if isinstance(path, str) and path:
            raw_outputs[key] = read_artifact_payload(Path(path))

    if raw_outputs:
        result["raw_outputs"] = raw_outputs


def pick_file(prefix_dir: Path, startswith: str) -> Optional[Path]:
    candidates = sorted(
        [p for p in prefix_dir.iterdir() if p.is_file() and p.name.startswith(startswith)],
        key=lambda item: item.name,
    )
    return candidates[0] if candidates else None


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def file_info(path: Path) -> Dict[str, Any]:
    info: Dict[str, Any] = {"path": str(path)}
    if path.exists():
        info["bytes"] = path.stat().st_size
        try:
            info["lines"] = path.read_bytes().count(b"\n")
        except Exception:
            pass
    return info


def add_artifact(result: Dict[str, Any], key: str, path: Path) -> None:
    result[key] = str(path)
    result.setdefault("artifacts", {})[key] = file_info(path)


def summarize_nmap(data: Dict[str, Any]) -> Dict[str, Any]:
    hosts = as_list(data.get("nmaprun", {}).get("host"))
    open_ports = []
    for host in hosts:
        if not isinstance(host, dict):
            continue
        for port in as_list(host.get("ports", {}).get("port")):
            if not isinstance(port, dict):
                continue
            state = port.get("state", {})
            if isinstance(state, dict) and state.get("@state") != "open":
                continue
            service = port.get("service", {})
            open_ports.append(
                {
                    "port": port.get("@portid"),
                    "protocol": port.get("@protocol"),
                    "service": service.get("@name") if isinstance(service, dict) else None,
                    "product": service.get("@product") if isinstance(service, dict) else None,
                    "version": service.get("@version") if isinstance(service, dict) else None,
                }
            )
    return {"hosts": len(hosts), "open_ports": open_ports}


def summarize_nikto(data: Any, limit: int = 50) -> Dict[str, Any]:
    vulnerabilities = []
    for host_result in as_list(data):
        if not isinstance(host_result, dict):
            continue
        for finding in as_list(host_result.get("vulnerabilities")):
            if not isinstance(finding, dict):
                continue
            vulnerabilities.append(
                {
                    "id": finding.get("id"),
                    "method": finding.get("method"),
                    "url": finding.get("url"),
                    "msg": finding.get("msg"),
                    "references": finding.get("references"),
                }
            )
    return {"vulnerabilities_count": len(vulnerabilities), "sample": vulnerabilities[:limit]}


def summarize_zap(data: Any, limit: int = 50) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    insights = [item for item in as_list(data.get("insights")) if isinstance(item, dict)]
    alert_count = 0
    alerts = []
    for site in as_list(data.get("site")):
        if not isinstance(site, dict):
            continue
        for alert in as_list(site.get("alerts")):
            if not isinstance(alert, dict):
                continue
            alert_count += 1
            if len(alerts) < limit:
                alerts.append(
                    {
                        "name": alert.get("name"),
                        "riskdesc": alert.get("riskdesc"),
                        "desc": alert.get("desc"),
                    }
                )
    levels = Counter(str(item.get("level", "Unknown")) for item in insights)
    return {
        "insights_count": len(insights),
        "insight_levels": dict(levels),
        "alerts_count": alert_count,
        "sample_alerts": alerts,
    }


def summarize_ffuf(data: Any, limit: int = 100) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    results = [item for item in as_list(data.get("results")) if isinstance(item, dict)]
    status_counts = Counter(str(item.get("status", "unknown")) for item in results)
    length_counts = Counter(str(item.get("length", "unknown")) for item in results)
    sample = []
    for item in results[:limit]:
        fuzz = item.get("input", {}).get("FUZZ") if isinstance(item.get("input"), dict) else None
        sample.append(
            {
                "path": fuzz,
                "status": item.get("status"),
                "length": item.get("length"),
                "words": item.get("words"),
                "lines": item.get("lines"),
                "url": item.get("url"),
            }
        )
    return {
        "results_count": len(results),
        "status_counts": dict(status_counts),
        "top_lengths": dict(length_counts.most_common(10)),
        "sample": sample,
    }


def summarize_whatweb(data: Any) -> Dict[str, Any]:
    entries = [item for item in as_list(data) if isinstance(item, dict)]
    plugins = []
    for entry in entries:
        plugins.extend(sorted((entry.get("plugins") or {}).keys()))
    return {"entries_count": len(entries), "plugins": sorted(set(plugins))}


def summarize_httpx(data: Any) -> Dict[str, Any]:
    if not isinstance(data, dict):
        return {}
    keep = [
        "url",
        "host",
        "host_ip",
        "port",
        "scheme",
        "title",
        "webserver",
        "tech",
        "status_code",
        "content_type",
        "content_length",
        "location",
        "failed",
    ]
    return {key: data.get(key) for key in keep if key in data}


def summarize_nuclei(records: List[Any], limit: int = 50) -> Dict[str, Any]:
    findings = [item for item in records if isinstance(item, dict)]
    severity_counts = Counter(
        str((item.get("info") or {}).get("severity", "unknown")) for item in findings
    )
    sample = []
    for item in findings[:limit]:
        info = item.get("info") or {}
        sample.append(
            {
                "template_id": item.get("template-id"),
                "matched_at": item.get("matched-at"),
                "severity": info.get("severity"),
                "name": info.get("name"),
            }
        )
    return {
        "findings_count": len(findings),
        "severity_counts": dict(severity_counts),
        "sample": sample,
    }


def summarize_lines(path: Path, limit: int = 100) -> Dict[str, Any]:
    if not path.exists():
        return {}
    lines = [line.strip() for line in path.read_text(encoding="utf-8", errors="replace").splitlines()]
    interesting = [
        line
        for line in lines
        if line
        and not line.startswith(("-", "+ End Time", "+ Start Time", "START_TIME", "END_TIME"))
    ]
    return {"lines": len(lines), "sample": interesting[:limit]}


def is_ip_address(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def domain_target(target: Dict[str, Any]) -> Optional[str]:
    domain = str(target.get("domain") or "").strip()
    if domain:
        return domain
    host = str(target.get("host") or "").strip()
    if not host or is_ip_address(host) or "." not in host:
        return None
    return host


def http_response_info(url: str, status: int, body: bytes, headers: Any) -> Dict[str, Any]:
    text = body.decode("utf-8", errors="replace")
    return {
        "url": url,
        "status": status,
        "length": len(body),
        "words": len(text.split()),
        "lines": len(text.splitlines()),
        "location": headers.get("Location") if headers else None,
    }


def baseline_response(url: str) -> Optional[Dict[str, Any]]:
    probe_url = f"{url.rstrip('/')}/__scanlab_missing_{uuid4().hex}"
    request = Request(probe_url, headers={"User-Agent": "scanlab-baseline"})
    try:
        with NO_REDIRECT_OPENER.open(request, timeout=5) as response:
            body = response.read()
            return http_response_info(probe_url, response.status, body, response.headers)
    except HTTPError as exc:
        body = exc.read()
        return http_response_info(probe_url, exc.code, body, exc.headers)
    except (OSError, URLError):
        return None


def run_nmap(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    xml_path = outdir / "nmap.xml"
    json_path = outdir / "nmap.json"
    result = run_command(
        [
            "nmap",
            "-sT",
            "-sV",
            "-Pn",
            "-p-",
            "--min-rate",
            "1000",
            "-oX",
            str(xml_path),
            target_host(target),
        ],
        outdir / "nmap.log",
        timeout=1800,
    )
    if xml_path.exists():
        try:
            parsed = xmltodict.parse(xml_path.read_text(encoding="utf-8"))
            json_path.write_text(json.dumps(parsed, indent=2, ensure_ascii=False), encoding="utf-8")
            add_artifact(result, "artifact_json", json_path)
            result["summary"] = summarize_nmap(parsed)
        except Exception as exc:
            result["parse_error"] = str(exc)
    return result


def run_nikto(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    result = run_command(
        ["nikto", "-h", target_url(target), "-Format", "json", "-o", str(outdir / "nikto")],
        outdir / "nikto.log",
        timeout=1800,
    )
    artifact = pick_file(outdir, "nikto")
    if artifact is not None:
        parsed = read_json(artifact)
        add_artifact(result, "artifact_json", artifact)
        if parsed is not None:
            result["summary"] = summarize_nikto(parsed)
    return result


def run_zap(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    json_path = outdir / "zap.json"
    result = run_command(
        ["zaproxy", "-cmd", "-quickurl", target_url(target), "-quickout", str(json_path)],
        outdir / "zap.log",
        timeout=1800,
    )
    if json_path.exists():
        add_artifact(result, "artifact_json", json_path)
        parsed = read_json(json_path)
        if parsed is not None:
            result["summary"] = summarize_zap(parsed)
    return result


def run_ffuf(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    json_path = outdir / "ffuf.json"
    baseline = baseline_response(target_url(target))
    cmd = [
        "ffuf",
        "-w",
        "/usr/share/dirb/wordlists/common.txt",
        "-u",
        f"{target_url(target).rstrip('/')}/FUZZ",
        "-mc",
        "200,301,302,403",
        "-o",
        str(json_path),
        "-of",
        "json",
        "-ac",
    ]
    if baseline:
        length = baseline.get("length")
        words = baseline.get("words")
        lines = baseline.get("lines")
        if isinstance(length, int):
            cmd.extend(["-fs", str(length)])
        if isinstance(words, int) and words > 0:
            cmd.extend(["-fw", str(words)])
        if isinstance(lines, int) and lines > 0:
            cmd.extend(["-fl", str(lines)])
    result = run_command(
        cmd,
        outdir / "ffuf.log",
        timeout=1800,
    )
    if baseline is not None:
        result["baseline"] = baseline
    if json_path.exists():
        add_artifact(result, "artifact_json", json_path)
        parsed = read_json(json_path)
        if parsed is not None:
            result["summary"] = summarize_ffuf(parsed)
    return result


def run_gobuster(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    baseline = baseline_response(target_url(target))
    cmd = [
        "gobuster",
        "dir",
        "-w",
        "/usr/share/dirb/wordlists/common.txt",
        "-u",
        target_url(target),
        "-q",
    ]
    if baseline:
        status = baseline.get("status")
        length = baseline.get("length")
        if status in (301, 302):
            cmd.extend(["-b", str(status)])
        if isinstance(length, int):
            cmd.extend(["--exclude-length", str(length)])
    result = run_command(
        cmd,
        outdir / "gobuster.log",
        timeout=1800,
    )
    if baseline is not None:
        result["baseline"] = baseline
    return result


def run_whatweb(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    json_path = outdir / "whatweb.json"
    result = run_command(
        ["whatweb", "--log-json", str(json_path), target_url(target)],
        outdir / "whatweb.log",
        timeout=900,
    )
    if json_path.exists():
        add_artifact(result, "artifact_json", json_path)
        parsed = read_json(json_path)
        if parsed is not None:
            result["summary"] = summarize_whatweb(parsed)
    return result


def run_testssl(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    parsed = urlparse(target_url(target))
    if parsed.scheme != "https" and int(target.get("port") or 80) not in (443, 8443):
        return {"skipped": True, "reason": "non_tls_target"}
    host = parsed.hostname or target_host(target)
    port = parsed.port or 443
    return run_command(
        ["testssl.sh", "--fast", f"{host}:{port}"],
        outdir / "testssl.log",
        timeout=2400,
    )


def run_dirb(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    log_path = outdir / "dirb.log"
    result = run_command(
        ["dirb", target_url(target), "/usr/share/dirb/wordlists/common.txt"],
        log_path,
        timeout=1800,
    )
    add_artifact(result, "artifact_log", log_path)
    result["summary"] = summarize_lines(log_path)
    return result


def run_sqlmap(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    log_path = outdir / "sqlmap.log"
    sqlmap_targets = target.get("sqlmap_targets")
    if isinstance(sqlmap_targets, list) and sqlmap_targets:
        target_file = outdir / "sqlmap-targets.txt"
        ensure_dir(outdir)
        target_file.write_text("\n".join(str(item) for item in sqlmap_targets), encoding="utf-8")
        cmd = [
            "sqlmap",
            "-m",
            str(target_file),
            "--batch",
            "--random-agent",
            "--output-dir",
            str(outdir / "sqlmap"),
        ]
    else:
        parsed = urlparse(target_url(target))
        if not parsed.query and not target.get("sqlmap_data"):
            return {
                "skipped": True,
                "reason": "no_query_or_post_parameters",
                "note": "Provide target.sqlmap_targets or target.sqlmap_data for meaningful sqlmap scans.",
            }
        cmd = [
            "sqlmap",
            "-u",
            target_url(target),
            "--batch",
            "--random-agent",
            "--output-dir",
            str(outdir / "sqlmap"),
        ]
        if target.get("sqlmap_data"):
            cmd.extend(["--data", str(target["sqlmap_data"])])
    result = run_command(
        cmd,
        log_path,
        timeout=2400,
    )
    add_artifact(result, "artifact_log", log_path)
    result["summary"] = summarize_lines(log_path)
    return result


def run_nuclei(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    nuclei = shutil.which("nuclei") or "nuclei"
    json_path = outdir / "nuclei.jsonl"
    templates_dir = Path("/root/nuclei-templates")
    if not templates_dir.exists() or not any(templates_dir.iterdir()):
        return {
            "skipped": True,
            "reason": "missing_nuclei_templates",
            "note": "Install templates in the scanner image or mount them at /root/nuclei-templates.",
        }
    result = run_command(
        [nuclei, "-u", target_url(target), "-templates", str(templates_dir), "-j", "-o", str(json_path)],
        outdir / "nuclei.log",
        timeout=1800,
    )
    if json_path.exists():
        add_artifact(result, "artifact_jsonl", json_path)
        result["summary"] = summarize_nuclei(read_jsonl(json_path))
    return result


def run_httpx(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    httpx = shutil.which("httpx") or "httpx"
    json_path = outdir / "httpx.json"
    result = run_command(
        [httpx, "-u", target_url(target), "-json", "-o", str(json_path)],
        outdir / "httpx.log",
        timeout=900,
    )
    if json_path.exists():
        add_artifact(result, "artifact_json", json_path)
        parsed = read_json(json_path)
        if parsed is not None:
            result["summary"] = summarize_httpx(parsed)
    return result


def run_subfinder(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    subfinder = shutil.which("subfinder") or "subfinder"
    host = domain_target(target)
    if not host:
        return {"skipped": True, "reason": "no_domain_target"}
    text_path = outdir / "subfinder.txt"
    result = run_command(
        [subfinder, "-d", host, "-silent", "-o", str(text_path)],
        outdir / "subfinder.log",
        timeout=1800,
    )
    if text_path.exists():
        add_artifact(result, "artifact_text", text_path)
        result["summary"] = summarize_lines(text_path)
    return result


def run_amass(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    amass = shutil.which("amass") or "amass"
    host = domain_target(target)
    if not host:
        return {"skipped": True, "reason": "no_domain_target"}
    text_path = outdir / "amass.txt"
    result = run_command(
        [amass, "enum", "-d", host, "-o", str(text_path)],
        outdir / "amass.log",
        timeout=2400,
    )
    if text_path.exists():
        add_artifact(result, "artifact_text", text_path)
        result["summary"] = summarize_lines(text_path)
    return result


def run_metasploit(target: Dict[str, Any], outdir: Path) -> Dict[str, Any]:
    host = target_host(target)
    port = int(target.get("port") or 80)
    msf_cmd = (
        f"use auxiliary/scanner/http/http_version; set RHOSTS {host}; set RPORT {port}; run; "
        f"use auxiliary/scanner/http/dir_scanner; set RHOSTS {host}; set RPORT {port}; run; "
        "exit"
    )
    log_path = outdir / "metasploit.log"
    result = run_command(
        ["msfconsole", "-q", "-x", msf_cmd],
        log_path,
        timeout=3600,
    )
    add_artifact(result, "artifact_log", log_path)
    result["summary"] = summarize_lines(log_path)
    return result


TOOL_RUNNERS = {
    "nmap": run_nmap,
    "nikto": run_nikto,
    "zaproxy": run_zap,
    "ffuf": run_ffuf,
    "gobuster": run_gobuster,
    "whatweb": run_whatweb,
    "testssl": run_testssl,
    "dirb": run_dirb,
    "sqlmap": run_sqlmap,
    "nuclei": run_nuclei,
    "httpx": run_httpx,
    "subfinder": run_subfinder,
    "amass": run_amass,
    "metasploit": run_metasploit,
}


def scan_target(target: Dict[str, Any], target_dir: Path, tools: List[str]) -> Dict[str, Any]:
    ensure_dir(target_dir)
    tool_results: Dict[str, Any] = {}
    for tool in tools:
        runner = TOOL_RUNNERS.get(tool)
        if runner is None:
            tool_results[tool] = {"skipped": True, "reason": "unknown_tool"}
            continue
        print(f"[tool] {target.get('id')} -> {tool}", flush=True)
        tool_result = runner(target, target_dir / tool)
        attach_raw_outputs(tool_result)
        tool_results[tool] = tool_result
    return {
        "id": target.get("id"),
        "name": target.get("name"),
        "kind": target.get("kind"),
        "ip": target.get("ip"),
        "host": target.get("host"),
        "url": target.get("url"),
        "port": target.get("port"),
        "tool_results": tool_results,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Multi-target network scanner runner")
    parser.add_argument("--targets-file", required=True, help="YAML target list")
    parser.add_argument("--output-dir", default="runs", help="Run output directory")
    parser.add_argument(
        "--profile",
        choices=sorted(TOOL_PROFILES.keys()),
        default="default",
        help="Tool profile to run. default keeps the old baseline plus stable current tools.",
    )
    parser.add_argument(
        "--tools",
        nargs="*",
        default=None,
        help="Explicit tool subset to run. Overrides --profile when provided.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    run_id = now_run_id()
    base_dir = Path(args.output_dir) / run_id
    ensure_dir(base_dir)
    ensure_dir(Path(args.output_dir))

    targets = load_targets(args.targets_file)
    tools = args.tools if args.tools is not None else list(TOOL_PROFILES[args.profile])
    bundle = {
        "metadata": {
            "run_id": run_id,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "targets_file": args.targets_file,
            "profile": args.profile,
            "tools": tools,
            "old_baseline_tools": OLD_BASELINE_TOOLS,
            "optional_tools": OPTIONAL_TOOLS,
        },
        "targets": [],
    }

    for target in targets:
        target_id = safe_name(str(target.get("id") or target.get("name") or target_host(target)))
        print(f"[scan] {target_id}", flush=True)
        result = scan_target(target, base_dir / target_id, tools)
        bundle["targets"].append(result)

    aggregated_path = base_dir / "aggregated_scan.json"
    aggregated_path.write_text(json.dumps(bundle, indent=2, ensure_ascii=False), encoding="utf-8")
    latest_path = Path(args.output_dir) / "latest"
    if latest_path.exists() or latest_path.is_symlink():
        latest_path.unlink()
    latest_path.symlink_to(base_dir.name)
    print(f"[done] wrote {aggregated_path}", flush=True)


if __name__ == "__main__":
    main()

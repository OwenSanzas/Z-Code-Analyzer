#!/usr/bin/env python3
"""Retry failed/false-positive projects from source batch with --force."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)
os.environ["PYTHONUNBUFFERED"] = "1"

RESULTS_FILE = Path("source_batch_results.json")
RETRY_LIST = Path("/tmp/source_retry_list.txt")
RETRY_RESULTS_FILE = Path("source_retry_results.json")


def load_results() -> dict:
    if RESULTS_FILE.exists():
        return json.loads(RESULTS_FILE.read_text())
    return {}


def save_results(results: dict) -> None:
    RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str))


def save_retry_results(results: dict) -> None:
    RETRY_RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str))


def run_project(name: str, repo_url: str) -> dict:
    """Run source pipeline for a single project with --force."""
    import re

    cmd = [
        sys.executable, "-m", "z_code_analyzer",
        "source", repo_url,
        "--project", name,
        "--force",
    ]

    # Kill any leftover containers
    for prefix in ("zca-src-", "zca-svf-"):
        try:
            r = subprocess.run(
                ["docker", "ps", "-q", "--filter", f"name={prefix}{name}"],
                capture_output=True, text=True, timeout=5,
            )
            for cid in r.stdout.strip().split():
                if cid:
                    subprocess.run(["docker", "kill", cid], capture_output=True, timeout=5)
        except Exception:
            pass

    t0 = time.time()
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=1200,
        )
        duration = round(time.time() - t0, 1)
        output = result.stdout + result.stderr

        _final_success = "— SUCCESS" in output and "— FAILED" not in output
        if _final_success:
            m = re.search(r"Functions:\s*(\d+)\s*\((\d+)\s*internal,\s*(\d+)\s*external\)", output)
            edges_m = re.search(r"Call edges:\s*(\d+)", output)
            return {
                "status": "success",
                "functions": int(m.group(1)) if m else 0,
                "internal": int(m.group(2)) if m else 0,
                "external": int(m.group(3)) if m else 0,
                "edges": int(edges_m.group(1)) if edges_m else 0,
                "duration": duration,
                "repo": repo_url,
            }
        else:
            error = ""
            for line in output.split("\n"):
                if "FATAL" in line or "Error" in line or "FAILED" in line:
                    error = line.strip()[:200]
                    break
            if not error:
                error = output[-300:].strip()
            return {
                "status": "failed",
                "error": error,
                "duration": duration,
                "repo": repo_url,
            }
    except subprocess.TimeoutExpired:
        for prefix in ("zca-src-", "zca-svf-"):
            try:
                r = subprocess.run(
                    ["docker", "ps", "-q", "--filter", f"name={prefix}{name}"],
                    capture_output=True, text=True, timeout=5,
                )
                for cid in r.stdout.strip().split():
                    if cid:
                        subprocess.run(["docker", "rm", "-f", cid], capture_output=True, timeout=10)
            except Exception:
                pass
        return {
            "status": "timeout",
            "duration": round(time.time() - t0, 1),
            "repo": repo_url,
        }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e)[:200],
            "duration": round(time.time() - t0, 1),
            "repo": repo_url,
        }


def main():
    # Load retry list
    projects = []
    with open(RETRY_LIST) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|", 1)
            if len(parts) == 2:
                projects.append((parts[0], parts[1]))

    print(f"Retry projects: {len(projects)}")

    # Load existing batch results (will update in-place)
    batch_results = load_results()
    retry_results = {}

    success = 0
    failed = 0
    improved = 0

    for i, (name, repo) in enumerate(projects):
        print(f"\n[{i+1}/{len(projects)}] {name} — {repo}")
        old = batch_results.get(name, {})
        old_fn = old.get('functions', 0)

        r = run_project(name, repo)
        retry_results[name] = r

        if r["status"] == "success":
            success += 1
            new_fn = r['functions']
            delta = f" (was {old_fn})" if new_fn != old_fn else ""
            if new_fn > old_fn:
                improved += 1
                delta = f" ↑ (was {old_fn})"
            print(f"  ✓ {r['internal']} internal, {r['functions']} total, {r['edges']} edges ({r['duration']}s){delta}")
        else:
            failed += 1
            print(f"  ✗ {r['status']}: {r.get('error', '')[:100]} ({r.get('duration', 0)}s)")

        # Update main results
        batch_results[name] = r
        save_results(batch_results)
        save_retry_results(retry_results)

        # Clean up staging
        subprocess.run(
            ["sudo", "find", "/home/ze/zca-staging", "-maxdepth", "1",
             "-name", "source-*", "-type", "d", "-exec", "rm", "-rf", "{}", "+"],
            capture_output=True, timeout=30,
        )
        subprocess.run(
            ["sudo", "find", "/home/ze/zca-staging", "-maxdepth", "1",
             "-name", "svf-*", "-type", "d", "-exec", "rm", "-rf", "{}", "+"],
            capture_output=True, timeout=30,
        )

        print(f"  Progress: {success} success, {failed} failed, {improved} improved, {len(projects)-i-1} remaining")

    print(f"\n{'='*60}")
    print(f"RETRY COMPLETE: {success} success, {failed} failed, {improved} improved out of {len(projects)}")
    print(f"Results updated in {RESULTS_FILE}")
    print(f"Retry details in {RETRY_RESULTS_FILE}")


if __name__ == "__main__":
    main()

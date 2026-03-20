#!/usr/bin/env python3
"""Batch runner for source pipeline — runs all oss-fuzz C/C++ projects."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path

# Unbuffered output
sys.stdout.reconfigure(line_buffering=True)
sys.stderr.reconfigure(line_buffering=True)
os.environ["PYTHONUNBUFFERED"] = "1"

RESULTS_FILE = Path("source_batch_results.json")
PROJECT_LIST = Path("/tmp/ossfuzz_github_projects.txt")
MAX_CONCURRENT = 1  # sequential — each project uses Docker


def load_results() -> dict:
    if RESULTS_FILE.exists():
        return json.loads(RESULTS_FILE.read_text())
    return {}


def save_results(results: dict) -> None:
    RESULTS_FILE.write_text(json.dumps(results, indent=2, default=str))


def run_project(name: str, repo_url: str, force: bool = False) -> dict:
    """Run source pipeline for a single project."""
    cmd = [
        sys.executable, "-m", "z_code_analyzer",
        "source", repo_url,
        "--project", name,
    ]
    if force:
        cmd.append("--force")

    # Kill any leftover containers for this project (best-effort)
    try:
        r = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=zca-src-{name}"],
            capture_output=True, text=True, timeout=5,
        )
        for cid in r.stdout.strip().split():
            if cid:
                subprocess.run(["docker", "kill", cid], capture_output=True, timeout=5)
        r = subprocess.run(
            ["docker", "ps", "-q", "--filter", f"name=zca-svf-{name}"],
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
            cmd,
            capture_output=True,
            text=True,
            timeout=1200,  # 20 min max per project
        )
        duration = round(time.time() - t0, 1)
        output = result.stdout + result.stderr

        # Parse result from output — check the FINAL summary line
        # (Docker script may print SUCCESS but Python quality gate may override with FAILED)
        _final_success = "— SUCCESS" in output and "— FAILED" not in output
        if _final_success:
            # Extract function count
            import re
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
            # Extract error
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
        # Kill any leftover containers aggressively
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


# Skip known-problematic projects (massive repos, unkillable containers, etc.)
SKIP_PROJECTS = {
    "apache-doris",     # 20GB+ repo, clone timeout issues
    "chromium",         # too large
    "llvm-project",     # too large
    "gcc",              # too large
    "linux",            # too large
    "gecko-dev",        # Firefox engine, too large
    "v8",               # too large (needs depot_tools)
    "angle",            # chromium-based, not github
    "skia",             # too large
    "android",          # too large
}


def main():
    force = "--force" in sys.argv

    # Load project list
    projects = []
    with open(PROJECT_LIST) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 3:
                name = parts[0]
                if name in SKIP_PROJECTS:
                    continue
                projects.append((name, parts[1], parts[2]))

    print(f"Total projects: {len(projects)}")

    # Load existing results
    results = load_results()

    # Filter already completed (unless --force)
    if not force:
        todo = [(n, l, r) for n, l, r in projects if n not in results or results[n].get("status") != "success"]
    else:
        todo = projects

    print(f"To process: {len(todo)} (skipping {len(projects) - len(todo)} completed)")

    success = sum(1 for v in results.values() if v.get("status") == "success")
    failed = sum(1 for v in results.values() if v.get("status") != "success")

    for i, (name, lang, repo) in enumerate(todo):
        print(f"\n[{i+1}/{len(todo)}] {name} ({lang}) — {repo}")
        t = time.time()
        r = run_project(name, repo, force=force)
        results[name] = r

        if r["status"] == "success":
            success += 1
            print(f"  ✓ {r['internal']} internal, {r['functions']} total, {r['edges']} edges ({r['duration']}s)")
        else:
            failed += 1
            print(f"  ✗ {r['status']}: {r.get('error', '')[:100]} ({r['duration']}s)")

        # Save after each project
        save_results(results)

        # Clean up staging after each run
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

        elapsed = time.time() - t
        print(f"  Progress: {success} success, {failed} failed, {len(todo)-i-1} remaining")

    # Final summary
    print(f"\n{'='*60}")
    print(f"BATCH COMPLETE: {success} success, {failed} failed out of {len(projects)} projects")
    print(f"Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()

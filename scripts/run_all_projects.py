#!/usr/bin/env python3
"""Batch run Z-Code-Analyzer on all 46 AGF benchmark projects.

For each project:
1. Build via OSS-Fuzz Docker (wllvm instrumented)
2. Extract call graph via SVF
3. Import into Neo4j
4. Compute fuzzer reachability for each case

Output: /home/ze/Z-Code-Analyzer/results/batch_results.json
"""

import json
import logging
import os
import sys
import time
from pathlib import Path

# Ensure the venv packages are available
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from z_code_analyzer.auto_pipeline import AutoAnalysisRequest, AutoPipeline
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.models.snapshot import ZCABase
from z_code_analyzer.snapshot_manager import SnapshotManager

# ── Config ──────────────────────────────────────────────────────────────────

NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = None  # no auth
PG_URL = "postgresql://postgres:postgres@localhost:5432/z_code_analyzer"
OSSFUZZ_REPO = "/home/ze/oss-fuzz"
RESULTS_DIR = Path("/home/ze/Z-Code-Analyzer/results")
RESULTS_FILE = RESULTS_DIR / "batch_results.json"
MAX_RETRIES = 3

# ── Project list from AGF benchmark (46 projects, 94 cases) ────────────────

def load_projects():
    """Load project-to-fuzzer mapping from AGF benchmark_cases.jsonl."""
    skipped = {"angle", "bluez", "duckdb", "ntpsec"}
    cases_file = Path("/home/ze/agf/benchmark/oss_fuzz_harness/data/benchmark_cases.jsonl")
    projects = {}
    with open(cases_file) as f:
        for line in f:
            c = json.loads(line)
            p = c["project"]
            if p in skipped:
                continue
            if p not in projects:
                projects[p] = []
            fuzzer = c.get("fuzzer_name", c.get("case_id", ""))
            if fuzzer not in projects[p]:
                projects[p].append(fuzzer)
    return dict(sorted(projects.items()))


def run_project(pipeline, project_name, fuzzers, attempt=1):
    """Run analysis for a single project. Returns result dict."""
    print(f"\n{'='*70}")
    print(f"  [{attempt}] PROJECT: {project_name} ({len(fuzzers)} fuzzers)")
    print(f"  Fuzzers: {', '.join(fuzzers)}")
    print(f"{'='*70}")

    request = AutoAnalysisRequest(
        ossfuzz_project=project_name,
        ossfuzz_repo_path=OSSFUZZ_REPO,
        force=(attempt > 1),  # force on retry
    )

    t0 = time.monotonic()
    try:
        result = pipeline.run(request)
        elapsed = time.monotonic() - t0

        print(result.summary())

        return {
            "project": project_name,
            "success": result.success,
            "snapshot_id": result.snapshot_id,
            "function_count": result.function_count,
            "edge_count": result.edge_count,
            "fuzzer_names_detected": result.fuzzer_names,
            "fuzzer_reach_count": result.fuzzer_reach_count,
            "build_duration_sec": result.build_duration_sec,
            "svf_duration_sec": result.svf_duration_sec,
            "import_duration_sec": result.import_duration_sec,
            "total_duration_sec": result.total_duration_sec,
            "error": result.error,
            "error_phase": result.error_phase,
            "benchmark_fuzzers": fuzzers,
            "attempt": attempt,
        }
    except Exception as e:
        elapsed = time.monotonic() - t0
        print(f"  EXCEPTION: {e}")
        return {
            "project": project_name,
            "success": False,
            "error": str(e),
            "error_phase": "exception",
            "total_duration_sec": elapsed,
            "benchmark_fuzzers": fuzzers,
            "attempt": attempt,
        }


def query_reachability(gs, snapshot_id, fuzzer_names):
    """Query Neo4j for per-fuzzer reachability stats."""
    reach_results = {}
    for fuzzer in fuzzer_names:
        try:
            query = """
            MATCH (fz:Fuzzer {snapshot_id: $sid})
            WHERE fz.name CONTAINS $fuzzer_name
            OPTIONAL MATCH (fz)-[:REACHES]->(f:Function {snapshot_id: $sid})
            RETURN fz.name AS fuzzer, count(f) AS reachable_functions
            """
            records = gs.raw_query(query, {"sid": snapshot_id, "fuzzer_name": fuzzer})
            if records:
                for r in records:
                    reach_results[r["fuzzer"] or fuzzer] = r["reachable_functions"]
            else:
                reach_results[fuzzer] = 0
        except Exception as e:
            reach_results[fuzzer] = f"error: {e}"
    return reach_results


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Suppress noisy loggers
    logging.getLogger("neo4j").setLevel(logging.WARNING)
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    projects = load_projects()
    print(f"Loaded {len(projects)} projects, {sum(len(v) for v in projects.values())} total cases")

    # Connect to databases
    gs = GraphStore(NEO4J_URI, NEO4J_AUTH)
    engine = create_engine(PG_URL)
    ZCABase.metadata.create_all(engine)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine), graph_store=gs)

    pipeline = AutoPipeline(
        snapshot_manager=sm,
        graph_store=gs,
        ossfuzz_repo_path=OSSFUZZ_REPO,
        neo4j_uri=NEO4J_URI,
    )

    # Load existing results for resume
    all_results = []
    completed_projects = set()
    if RESULTS_FILE.exists():
        existing = json.loads(RESULTS_FILE.read_text())
        for r in existing:
            if r.get("success"):
                completed_projects.add(r["project"])
                all_results.append(r)
        print(f"Resuming: {len(completed_projects)} already completed")

    total = len(projects)
    succeeded = len(completed_projects)
    failed = 0

    try:
        for idx, (project_name, fuzzers) in enumerate(projects.items(), 1):
            if project_name in completed_projects:
                print(f"\n[{idx}/{total}] SKIP (already done): {project_name}")
                continue

            print(f"\n[{idx}/{total}] Starting: {project_name}")

            result = None
            for attempt in range(1, MAX_RETRIES + 1):
                result = run_project(pipeline, project_name, fuzzers, attempt)
                if result["success"]:
                    break
                if attempt < MAX_RETRIES:
                    print(f"  Retrying {project_name} (attempt {attempt + 1}/{MAX_RETRIES})...")

            # Query reachability if successful
            if result and result["success"] and result.get("snapshot_id"):
                try:
                    reach = query_reachability(gs, result["snapshot_id"], fuzzers)
                    result["case_reachability"] = reach
                except Exception as e:
                    result["case_reachability"] = {"error": str(e)}

            all_results.append(result)
            if result and result["success"]:
                succeeded += 1
            else:
                failed += 1

            # Save after each project (crash-safe)
            RESULTS_FILE.write_text(json.dumps(all_results, indent=2, default=str))
            print(f"\n  Progress: {succeeded} OK / {failed} FAIL / {total - succeeded - failed} remaining")

    except KeyboardInterrupt:
        print("\n\nInterrupted! Saving partial results...")
    finally:
        RESULTS_FILE.write_text(json.dumps(all_results, indent=2, default=str))
        gs.close()
        sm.close()

    print(f"\n{'='*70}")
    print(f"  FINAL: {succeeded}/{total} succeeded, {failed} failed")
    print(f"  Results: {RESULTS_FILE}")
    print(f"{'='*70}")


if __name__ == "__main__":
    main()

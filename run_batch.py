#!/usr/bin/env python3
"""Batch runner script — analyze oss-fuzz projects sequentially.

Tracks progress, skips already-completed projects, writes results to JSON.
"""

import json
import logging
import subprocess
import sys
import time
from pathlib import Path

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from z_code_analyzer.auto_pipeline import (
    AutoAnalysisRequest,
    AutoAnalysisResult,
    AutoPipeline,
)
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.snapshot_manager import SnapshotManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger("batch")

DB_URL = "postgresql://zca:zca_pass@127.0.0.1:5433/z_code_analyzer"
NEO4J_URI = "bolt://localhost:7687"
NEO4J_AUTH = None  # no auth on new container
OSSFUZZ_PATH = "/data2/ze/poc-workspace/oss-fuzz"
RESULTS_FILE = "/data2/ze/Z-Code-Analyzer/batch_results.json"


def get_completed_projects() -> set[str]:
    """Get project names already completed in PostgreSQL."""
    engine = create_engine(DB_URL)
    completed = set()
    with engine.connect() as conn:
        rows = conn.execute(
            text("SELECT repo_name FROM snapshots WHERE status = 'completed'")
        )
        for r in rows:
            name = r.repo_name
            # repo_name is like "libpng.git" — strip suffix
            if name.endswith(".git"):
                name = name[:-4]
            completed.add(name)
    engine.dispose()
    return completed


def get_available_projects() -> list[str]:
    """Get list of C/C++ projects that have Docker images available."""
    import subprocess
    import yaml

    # Get available Docker images
    result = subprocess.run(
        ["docker", "images", "--format", "{{.Repository}}"],
        capture_output=True, text=True, timeout=30,
    )
    images = set(result.stdout.strip().splitlines())

    projects_dir = Path(OSSFUZZ_PATH) / "projects"
    available = []

    for pdir in sorted(projects_dir.iterdir()):
        if not pdir.is_dir():
            continue
        yaml_file = pdir / "project.yaml"
        if not yaml_file.exists():
            continue
        try:
            data = yaml.safe_load(yaml_file.read_text())
            lang = str(data.get("language", "")).lower().strip()
            if lang not in ("c", "c++", "cpp"):
                continue
            image_name = f"gcr.io/oss-fuzz/{pdir.name}"
            if image_name in images:
                available.append(pdir.name)
        except Exception:
            continue

    return available


def load_results() -> dict:
    """Load existing results file."""
    if Path(RESULTS_FILE).exists():
        return json.loads(Path(RESULTS_FILE).read_text())
    return {"projects": {}, "summary": {}}


def save_results(results: dict) -> None:
    """Save results to file."""
    # Update summary
    projects = results["projects"]
    succeeded = sum(1 for v in projects.values() if v.get("success"))
    failed = sum(1 for v in projects.values() if not v.get("success"))
    results["summary"] = {
        "total": len(projects),
        "succeeded": succeeded,
        "failed": failed,
        "last_updated": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    Path(RESULTS_FILE).write_text(json.dumps(results, indent=2))


def run_single(pipeline: AutoPipeline, project_name: str) -> AutoAnalysisResult:
    """Run analysis for a single project."""
    request = AutoAnalysisRequest(
        ossfuzz_project=project_name,
        language="c",
        ossfuzz_repo_path=OSSFUZZ_PATH,
    )
    return pipeline.run(request)


def main():
    # Setup
    engine = create_engine(DB_URL)
    Session = sessionmaker(bind=engine)
    sm = SnapshotManager(Session)
    gs = GraphStore(NEO4J_URI, auth=NEO4J_AUTH)
    pipeline = AutoPipeline(
        snapshot_manager=sm,
        graph_store=gs,
        ossfuzz_repo_path=OSSFUZZ_PATH,
        neo4j_uri=NEO4J_URI,
        neo4j_auth=NEO4J_AUTH,
        workspace_dir="/data2/ze/Z-Code-Analyzer/workspace",
    )

    # Get project lists
    available = get_available_projects()
    completed = get_completed_projects()
    results = load_results()

    # Also mark previously recorded successes as completed
    for name, data in results.get("projects", {}).items():
        if data.get("success"):
            completed.add(name)

    todo = [p for p in available if p not in completed]
    logger.info(
        "Available: %d, Already completed: %d, To do: %d",
        len(available), len(completed), len(todo),
    )

    if not todo:
        logger.info("All available projects already completed!")
        return

    # Run projects sequentially
    t0 = time.monotonic()
    for i, project_name in enumerate(todo):
        logger.info(
            "=" * 60 + "\n[%d/%d] Starting: %s\n" + "=" * 60,
            i + 1, len(todo), project_name,
        )

        try:
            result = run_single(pipeline, project_name)
        except Exception as e:
            result = AutoAnalysisResult(
                success=False,
                project_name=project_name,
                error=str(e),
                error_phase="unknown",
            )

        results["projects"][project_name] = {
            "success": result.success,
            "snapshot_id": result.snapshot_id,
            "function_count": result.function_count,
            "edge_count": result.edge_count,
            "fuzzer_names": result.fuzzer_names,
            "fuzzer_reach_count": result.fuzzer_reach_count,
            "build_duration_sec": result.build_duration_sec,
            "svf_duration_sec": result.svf_duration_sec,
            "total_duration_sec": result.total_duration_sec,
            "error": result.error,
            "error_phase": result.error_phase,
        }
        save_results(results)

        status = "OK" if result.success else "FAILED"
        logger.info(
            "[%d/%d] %s: %s (funcs=%d edges=%d time=%.0fs)",
            i + 1, len(todo), project_name, status,
            result.function_count, result.edge_count,
            result.total_duration_sec,
        )
        if not result.success:
            logger.error("  Error: [%s] %s", result.error_phase, result.error[:200])

        # Remove the Docker image after successful processing to save disk
        # Keep images for failed projects so they can be retried
        if result.success:
            image_name = f"gcr.io/oss-fuzz/{project_name}"
            try:
                subprocess.run(
                    ["docker", "rmi", image_name],
                    capture_output=True, timeout=30,
                )
                logger.info("[%d/%d] Removed image %s", i + 1, len(todo), image_name)
            except Exception:
                pass

    elapsed = time.monotonic() - t0
    logger.info("\nBatch complete in %.0fs (%.1f min)", elapsed, elapsed / 60)

    # Print final summary
    projects = results["projects"]
    succeeded = sum(1 for v in projects.values() if v.get("success"))
    failed = sum(1 for v in projects.values() if not v.get("success"))
    logger.info("Succeeded: %d, Failed: %d, Total: %d", succeeded, failed, len(projects))

    if failed > 0:
        logger.info("\nFailed projects:")
        for name, data in sorted(projects.items()):
            if not data.get("success"):
                logger.info("  %s: [%s] %s", name, data.get("error_phase", "?"), data.get("error", "?")[:100])


if __name__ == "__main__":
    main()

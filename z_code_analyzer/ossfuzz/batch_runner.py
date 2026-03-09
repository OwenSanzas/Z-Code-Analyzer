"""Batch runner — analyze multiple oss-fuzz projects in sequence or parallel.

Handles:
- Project selection and prioritization
- Docker image pulling
- Sequential/parallel execution
- Progress tracking and reporting
- Failure recovery and retry
"""

from __future__ import annotations

import concurrent.futures
import json
import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from z_code_analyzer.auto_pipeline import (
    AutoAnalysisRequest,
    AutoAnalysisResult,
    AutoPipeline,
)
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.ossfuzz.crawler import OSSFuzzCrawler, OSSFuzzProject
from z_code_analyzer.snapshot_manager import SnapshotManager

logger = logging.getLogger(__name__)

_PULL_TIMEOUT = 600  # 10 min per image pull


@dataclass
class BatchResult:
    """Aggregate result of a batch analysis run."""

    total: int = 0
    succeeded: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[AutoAnalysisResult] = field(default_factory=list)
    total_functions: int = 0
    total_edges: int = 0
    total_duration_sec: float = 0.0

    def summary(self) -> str:
        """Human-readable batch summary."""
        lines = [
            f"Batch Analysis Summary",
            f"{'=' * 60}",
            f"Total:     {self.total}",
            f"Succeeded: {self.succeeded}",
            f"Failed:    {self.failed}",
            f"Skipped:   {self.skipped}",
            f"",
            f"Total Functions: {self.total_functions:,}",
            f"Total Edges:     {self.total_edges:,}",
            f"Total Duration:  {self.total_duration_sec:.1f}s "
            f"({self.total_duration_sec / 60:.1f}min)",
            f"",
        ]

        # Success list
        successes = [r for r in self.results if r.success]
        if successes:
            lines.append("Successful Projects:")
            for r in sorted(successes, key=lambda x: x.project_name):
                lines.append(
                    f"  {r.project_name:25s} funcs={r.function_count:6d} "
                    f"edges={r.edge_count:6d} fuzzers={len(r.fuzzer_names):2d} "
                    f"snap={r.snapshot_id[:12]}"
                )
            lines.append("")

        # Failure list
        failures = [r for r in self.results if not r.success]
        if failures:
            lines.append("Failed Projects:")
            for r in sorted(failures, key=lambda x: x.project_name):
                lines.append(
                    f"  {r.project_name:25s} phase={r.error_phase:10s} "
                    f"error={r.error[:80]}"
                )
            lines.append("")

        return "\n".join(lines)


class BatchRunner:
    """Run analysis on multiple oss-fuzz projects.

    Usage::

        runner = BatchRunner(
            snapshot_manager=sm,
            graph_store=gs,
            ossfuzz_repo_path="/path/to/oss-fuzz",
        )

        result = runner.run(limit=100, max_parallel=4)
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        ossfuzz_repo_path: str,
        neo4j_uri: str = "bolt://localhost:7687",
        workspace_dir: str = "",
    ) -> None:
        self._sm = snapshot_manager
        self._gs = graph_store
        self._ossfuzz_path = ossfuzz_repo_path
        self._neo4j_uri = neo4j_uri
        self._workspace_dir = workspace_dir or str(Path.cwd() / "workspace")
        self._pipeline = AutoPipeline(
            snapshot_manager=snapshot_manager,
            graph_store=graph_store,
            ossfuzz_repo_path=ossfuzz_repo_path,
            neo4j_uri=neo4j_uri,
            workspace_dir=self._workspace_dir,
        )

    def run(
        self,
        limit: int = 100,
        max_parallel: int = 1,
        retry_count: int = 1,
        projects: list[OSSFuzzProject] | None = None,
        project_names: list[str] | None = None,
        pull_images: bool = True,
        results_file: str = "",
    ) -> BatchResult:
        """Run batch analysis.

        Args:
            limit: Maximum number of projects to analyze.
            max_parallel: Max concurrent Docker builds.
            retry_count: Number of retries for failed projects.
            projects: Pre-selected projects (skip crawling).
            project_names: Specific project names to analyze.
            pull_images: Whether to pull missing Docker images.
            results_file: Path to write JSON results file.

        Returns:
            BatchResult with per-project results.
        """
        t0 = time.monotonic()
        batch = BatchResult()

        # Step 1: Select projects
        if projects:
            selected = projects[:limit]
        elif project_names:
            crawler = OSSFuzzCrawler(self._ossfuzz_path)
            selected = []
            for name in project_names[:limit]:
                p = crawler.get_project(name)
                if p:
                    selected.append(p)
                else:
                    logger.warning("Project '%s' not found in oss-fuzz", name)
            if not selected:
                raise ValueError("No valid projects found")
        else:
            crawler = OSSFuzzCrawler(self._ossfuzz_path)
            selected = crawler.crawl(limit=limit, require_docker_image=False)

        batch.total = len(selected)
        logger.info(
            "Batch: %d projects selected (%d with Docker image)",
            len(selected),
            sum(1 for p in selected if p.docker_image_available),
        )

        # Step 2: Pull missing Docker images
        if pull_images:
            self._pull_missing_images(selected)

        # Step 3: Run analysis
        if max_parallel <= 1:
            for i, project in enumerate(selected):
                logger.info(
                    "[%d/%d] Analyzing %s...",
                    i + 1,
                    len(selected),
                    project.name,
                )
                result = self._analyze_with_retry(project, retry_count)
                batch.results.append(result)
                if result.success:
                    batch.succeeded += 1
                    batch.total_functions += result.function_count
                    batch.total_edges += result.edge_count
                else:
                    batch.failed += 1
                self._write_progress(batch, results_file)
        else:
            # Parallel execution
            lock = threading.Lock()
            with concurrent.futures.ThreadPoolExecutor(
                max_workers=max_parallel
            ) as pool:
                futures = {
                    pool.submit(self._analyze_with_retry, p, retry_count): p
                    for p in selected
                }
                for i, future in enumerate(
                    concurrent.futures.as_completed(futures)
                ):
                    project = futures[future]
                    try:
                        result = future.result()
                    except Exception as e:
                        result = AutoAnalysisResult(
                            success=False,
                            project_name=project.name,
                            error=str(e),
                            error_phase="unknown",
                        )
                    with lock:
                        batch.results.append(result)
                        if result.success:
                            batch.succeeded += 1
                            batch.total_functions += result.function_count
                            batch.total_edges += result.edge_count
                        else:
                            batch.failed += 1
                        logger.info(
                            "[%d/%d] %s: %s (%d funcs, %d edges)",
                            batch.succeeded + batch.failed,
                            len(selected),
                            project.name,
                            "OK" if result.success else "FAILED",
                            result.function_count,
                            result.edge_count,
                        )
                        self._write_progress(batch, results_file)

        batch.total_duration_sec = round(time.monotonic() - t0, 2)

        # Write final results
        if results_file:
            self._write_results(batch, results_file)

        logger.info(batch.summary())
        return batch

    def _analyze_with_retry(
        self,
        project: OSSFuzzProject,
        retry_count: int,
    ) -> AutoAnalysisResult:
        """Analyze a single project with retries."""
        last_result = None
        for attempt in range(1, retry_count + 1):
            request = AutoAnalysisRequest(
                repo_url=project.main_repo,
                ossfuzz_project=project.name,
                language=_normalize_language(project.language),
                ossfuzz_repo_path=self._ossfuzz_path,
            )

            result = self._pipeline.run(request)
            last_result = result

            if result.success:
                return result

            if attempt < retry_count:
                logger.info(
                    "[%s] Attempt %d failed (%s), retrying...",
                    project.name,
                    attempt,
                    result.error_phase,
                )

        return last_result  # type: ignore[return-value]

    def _pull_missing_images(self, projects: list[OSSFuzzProject]) -> None:
        """Pull Docker images that aren't available locally."""
        to_pull = [
            p for p in projects
            if not p.docker_image_available and p.docker_image
        ]

        if not to_pull:
            logger.info("All Docker images already available")
            return

        logger.info("Pulling %d Docker images...", len(to_pull))

        # Also ensure svftools/svf is available
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", "svftools/svf"],
                capture_output=True,
                timeout=10,
            )
            if result.returncode != 0:
                logger.info("Pulling svftools/svf image...")
                subprocess.run(
                    ["docker", "pull", "svftools/svf"],
                    capture_output=True,
                    text=True,
                    timeout=_PULL_TIMEOUT,
                )
        except Exception as e:
            logger.warning("Failed to pull svftools/svf: %s", e)

        for i, project in enumerate(to_pull):
            logger.info(
                "Pulling [%d/%d] %s...",
                i + 1,
                len(to_pull),
                project.docker_image,
            )
            try:
                subprocess.run(
                    ["docker", "pull", project.docker_image],
                    capture_output=True,
                    text=True,
                    timeout=_PULL_TIMEOUT,
                )
                project.docker_image_available = True
            except subprocess.TimeoutExpired:
                logger.warning("Timeout pulling %s", project.docker_image)
            except subprocess.CalledProcessError as e:
                logger.warning(
                    "Failed to pull %s: %s",
                    project.docker_image,
                    e.stderr[:200] if e.stderr else str(e),
                )

    @staticmethod
    def _write_progress(batch: BatchResult, results_file: str) -> None:
        """Write intermediate progress to file."""
        if not results_file:
            return
        try:
            progress_file = results_file.replace(".json", ".progress.json")
            data = {
                "total": batch.total,
                "succeeded": batch.succeeded,
                "failed": batch.failed,
                "completed": batch.succeeded + batch.failed,
            }
            Path(progress_file).write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    @staticmethod
    def _write_results(batch: BatchResult, results_file: str) -> None:
        """Write final results to JSON file."""
        data = {
            "total": batch.total,
            "succeeded": batch.succeeded,
            "failed": batch.failed,
            "total_functions": batch.total_functions,
            "total_edges": batch.total_edges,
            "total_duration_sec": batch.total_duration_sec,
            "projects": [],
        }
        for r in sorted(batch.results, key=lambda x: x.project_name):
            data["projects"].append({
                "name": r.project_name,
                "success": r.success,
                "snapshot_id": r.snapshot_id,
                "repo_url": r.repo_url,
                "version": r.version,
                "function_count": r.function_count,
                "edge_count": r.edge_count,
                "fuzzer_names": r.fuzzer_names,
                "fuzzer_reach_count": r.fuzzer_reach_count,
                "build_duration_sec": r.build_duration_sec,
                "svf_duration_sec": r.svf_duration_sec,
                "total_duration_sec": r.total_duration_sec,
                "error": r.error,
                "error_phase": r.error_phase,
            })
        Path(results_file).write_text(json.dumps(data, indent=2))
        logger.info("Results written to %s", results_file)


def _normalize_language(lang: str) -> str:
    """Normalize oss-fuzz language field to our convention."""
    lang = lang.lower().strip()
    if lang in ("c++", "cpp"):
        return "c"  # SVF handles both C and C++ via LLVM IR
    return lang

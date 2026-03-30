"""Fully automated analysis pipeline — zero-config call graph extraction.

Given a repo URL (or oss-fuzz project name), this module:
1. Resolves the oss-fuzz Docker image (or builds one)
2. Runs the build inside Docker with wllvm instrumentation
3. Extracts library-only bitcode
4. Runs SVF pointer analysis for call graph
5. Parses fuzzer entry points
6. Imports everything into Neo4j
7. Creates a PostgreSQL snapshot record

No manual configuration required.
"""

from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from z_code_analyzer.backends.base import (
    AnalysisResult,
    CallEdge,
    CallType,
    FunctionRecord,
    FuzzerInfo,
)
from z_code_analyzer.build.bitcode import BitcodeGenerator
from z_code_analyzer.build.fuzzer_parser import FuzzerEntryParser
from z_code_analyzer.exceptions import BitcodeError, SVFError
from z_code_analyzer.graph_store import GraphStore
from z_code_analyzer.models.build import FunctionMeta
from z_code_analyzer.snapshot_manager import SnapshotManager
from z_code_analyzer.svf.svf_dot_parser import (
    get_all_function_names,
    get_typed_edge_list,
    parse_svf_dot_file,
)

logger = logging.getLogger(__name__)

# Timeouts — no limits for batch experiment
_DOCKER_BUILD_TIMEOUT = 36000  # 10 hours for oss-fuzz build
_SVF_ANALYSIS_TIMEOUT = 36000  # 10 hours for SVF pointer analysis
_DOCKER_PULL_TIMEOUT = 3600    # 1 hour for docker pull
_MAX_REACH_DEPTH = 20  # Reduced from 50 to prevent Neo4j OOM on large graphs

# Memory limits for Docker containers (prevent OOM on host)
_DOCKER_BUILD_MEMORY = "32g"  # oss-fuzz build container (increased for large projects)
_SVF_MEMORY = "32g"           # SVF pointer analysis (Andersen can be hungry)

# Known fuzzing framework files to exclude from project fuzzer list.
# These are infrastructure, not project-specific fuzzers.
# Pattern-based detection of fuzzing framework binaries.
# These are executables from libFuzzer, AFL++, centipede, honggfuzz etc. that
# end up in $OUT alongside the real project fuzzers.
_FRAMEWORK_BINARY_PATTERNS = [
    re.compile(r"^Fuzzer[A-Z]"),                    # libFuzzer: FuzzerDriver, FuzzerLoop, etc.
    re.compile(r"^FuzzedDataProvider"),              # FDP tests
    re.compile(r"^DataFlow"),                        # libFuzzer DataFlow
    re.compile(r"^Standalone"),                      # StandaloneFuzzTargetMain
    re.compile(r"^aflpp_|^afl_|^afl-"),             # AFL++/AFL
    re.compile(r"^centipede"),                       # Centipede (centipede, centipede_main, ...)
    re.compile(r"^runner_(fork|main|interceptors|sancov|dl_info|utils|cmp_trace)"),
    re.compile(r"^honggfuzz|^hfuzz"),               # Honggfuzz
    re.compile(r"^weak_sancov"),                     # Sanitizer stubs
    re.compile(r"\.so(\.\d+)*$"),                    # Shared libraries
]


def _is_framework_binary(name: str) -> bool:
    """Check if a binary name is a fuzzing framework component, not a project fuzzer."""
    return any(p.search(name) for p in _FRAMEWORK_BINARY_PATTERNS)


def _fuzzer_name_matches(binary_name: str, source_stem: str) -> bool:
    """Check if a fuzzer binary name plausibly matches a source file stem.

    Uses strict prefix matching (must be separated by _ or -) to avoid
    false matches like 'fuzztest_gtest_main' matching 'fuzz.c'.
    """
    if binary_name == source_stem:
        return True
    # Binary name is an extension of source name: fuzz_uri matches fuzz
    for sep in ("_", "-"):
        if binary_name.startswith(source_stem + sep):
            return True
        if source_stem.startswith(binary_name + sep):
            return True
    return False


@dataclass
class AutoAnalysisRequest:
    """Input for fully automated analysis."""

    # Required: at least one of these
    repo_url: str = ""
    ossfuzz_project: str = ""  # oss-fuzz project name (e.g., "libpng")

    # Optional overrides
    version: str = "HEAD"
    branch: str = ""
    language: str = ""  # auto-detect if empty
    fuzzer_names: list[str] = field(default_factory=list)
    backend: str = ""  # "svf", "joern", or "" (auto-select from project_configs)

    # OSS-Fuzz configuration
    ossfuzz_repo_path: str = ""  # path to local oss-fuzz repo
    docker_image: str = ""  # explicit Docker image override

    # Advanced
    project_path: str = ""  # local source path (skip clone)
    skip_svf: bool = False  # only produce bitcode
    workspace_dir: str = ""  # working directory
    force: bool = False  # force re-analysis even if snapshot exists


@dataclass
class AutoAnalysisResult:
    """Output of fully automated analysis."""

    success: bool
    project_name: str
    snapshot_id: str = ""
    repo_url: str = ""
    version: str = ""
    backend: str = "svf"
    function_count: int = 0
    edge_count: int = 0
    fuzzer_names: list[str] = field(default_factory=list)
    fuzzer_reach_count: int = 0

    # Timing
    build_duration_sec: float = 0.0
    svf_duration_sec: float = 0.0
    fuzzer_parse_duration_sec: float = 0.0
    import_duration_sec: float = 0.0
    total_duration_sec: float = 0.0

    # Error info
    error: str = ""
    error_phase: str = ""

    # Neo4j location
    neo4j_uri: str = ""
    neo4j_snapshot_id: str = ""

    def summary(self) -> str:
        """Human-readable summary."""
        if not self.success:
            return (
                f"FAILED: {self.project_name} @ {self.version}\n"
                f"  Phase: {self.error_phase}\n"
                f"  Error: {self.error}\n"
                f"  Duration: {self.total_duration_sec:.1f}s"
            )
        return (
            f"OK: {self.project_name} @ {self.version}\n"
            f"  Snapshot: {self.snapshot_id}\n"
            f"  Functions: {self.function_count}, Edges: {self.edge_count}\n"
            f"  Fuzzers: {self.fuzzer_names}\n"
            f"  Reaches: {self.fuzzer_reach_count}\n"
            f"  Build: {self.build_duration_sec:.1f}s, SVF: {self.svf_duration_sec:.1f}s, "
            f"Fuzzer: {self.fuzzer_parse_duration_sec:.1f}s, Import: {self.import_duration_sec:.1f}s, "
            f"Total: {self.total_duration_sec:.1f}s\n"
            f"  Neo4j: {self.neo4j_uri} (snapshot={self.neo4j_snapshot_id})"
        )


class AutoPipeline:
    """Fully automated analysis pipeline.

    Usage::

        pipeline = AutoPipeline(
            snapshot_manager=sm,
            graph_store=gs,
            ossfuzz_repo_path="/path/to/oss-fuzz",
        )

        result = pipeline.run(AutoAnalysisRequest(
            ossfuzz_project="libpng",
        ))
    """

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        ossfuzz_repo_path: str = "",
        neo4j_uri: str = "bolt://localhost:7687",
        neo4j_auth: tuple | None = None,
        workspace_dir: str = "",
    ) -> None:
        self._sm = snapshot_manager
        self._gs = graph_store
        self._ossfuzz_path = ossfuzz_repo_path
        self._neo4j_uri = neo4j_uri
        self._neo4j_auth = neo4j_auth
        self._workspace_dir = workspace_dir or str(Path.cwd() / "workspace")
        Path(self._workspace_dir).mkdir(parents=True, exist_ok=True)

    def _resolve_backend(self, request: AutoAnalysisRequest, project_name: str) -> str:
        """Determine which backend to use: 'svf' or 'joern'."""
        if request.backend:
            return request.backend

        # Check project_configs for preferred backend
        try:
            from z_code_analyzer.project_configs import get_config
            config = get_config(project_name)
            if config:
                return config.preferred_backend
        except ImportError:
            pass

        # Default to SVF
        return "svf"

    def run(self, request: AutoAnalysisRequest) -> AutoAnalysisResult:
        """Execute the full automated pipeline synchronously."""
        t0 = time.monotonic()
        project_name = request.ossfuzz_project or self._extract_project_name(
            request.repo_url
        )
        result = AutoAnalysisResult(
            success=False,
            project_name=project_name,
            repo_url=request.repo_url,
            version=request.version,
            neo4j_uri=self._neo4j_uri,
        )

        # Determine backend
        backend = self._resolve_backend(request, project_name)
        result.backend = backend

        if backend == "joern":
            return self._run_joern_pipeline(request, project_name, result, t0)

        output_dir = tempfile.mkdtemp(
            prefix=f"auto-{project_name}-",
            dir=self._workspace_dir,
        )

        try:
            # Phase 1: Resolve Docker image and project metadata
            docker_image, repo_url, build_sh_path = self._resolve_project(
                request, project_name
            )
            result.repo_url = repo_url

            # Phase 2: Run build inside Docker to produce bitcode
            logger.info("[%s] Phase 2: Building bitcode in Docker...", project_name)
            build_t0 = time.monotonic()
            self._run_docker_build(
                project_name=project_name,
                docker_image=docker_image,
                output_dir=output_dir,
                build_sh_path=build_sh_path,
                request=request,
            )
            result.build_duration_sec = round(time.monotonic() - build_t0, 2)

            bc_path = Path(output_dir) / "library.bc"
            if not bc_path.exists():
                raise BitcodeError(
                    f"library.bc not produced in {output_dir}"
                )
            logger.info(
                "[%s] Bitcode ready: %s (%s)",
                project_name,
                bc_path,
                _human_size(bc_path.stat().st_size),
            )

            # Phase 3: Parse .ll for function metadata
            logger.info("[%s] Phase 3: Parsing function metadata...", project_name)
            ll_path = Path(output_dir) / "library.ll"
            function_metas: list[FunctionMeta] = []
            if ll_path.exists() and ll_path.stat().st_size > 0:
                function_metas = BitcodeGenerator._parse_ll_debug_info(
                    ll_path, request.project_path or "/src/" + project_name,
                    docker_mount_name=project_name,
                )
                logger.info(
                    "[%s] Extracted %d function metas from .ll",
                    project_name,
                    len(function_metas),
                )

            # Phase 4: SVF analysis
            logger.info("[%s] Phase 4: Running SVF pointer analysis...", project_name)
            svf_t0 = time.monotonic()
            language = request.language or "c"
            analysis_result = self._run_svf(
                project_name=project_name,
                bc_path=str(bc_path),
                function_metas=function_metas,
                language=language,
                output_dir=output_dir,
            )
            result.svf_duration_sec = round(time.monotonic() - svf_t0, 2)
            result.function_count = len(analysis_result.functions)
            result.edge_count = len(analysis_result.edges)
            logger.info(
                "[%s] SVF complete: %d functions, %d edges",
                project_name,
                result.function_count,
                result.edge_count,
            )

            # Phase 5: Parse fuzzer sources
            logger.info("[%s] Phase 5: Parsing fuzzer sources...", project_name)
            fuzzer_t0 = time.monotonic()
            fuzzer_sources, fuzzer_calls = self._parse_fuzzers(
                project_name=project_name,
                output_dir=output_dir,
                library_functions={f.name for f in analysis_result.functions},
                request=request,
            )
            result.fuzzer_parse_duration_sec = round(time.monotonic() - fuzzer_t0, 2)

            # Phase 6: Import to Neo4j + create snapshot
            logger.info("[%s] Phase 6: Importing to Neo4j...", project_name)
            import_t0 = time.monotonic()
            snapshot_id = self._import_to_neo4j(
                project_name=project_name,
                repo_url=repo_url,
                version=request.version,
                analysis_result=analysis_result,
                fuzzer_sources=fuzzer_sources,
                fuzzer_calls=fuzzer_calls,
                language=language,
                force=request.force,
            )

            result.import_duration_sec = round(time.monotonic() - import_t0, 2)

            result.success = True
            result.snapshot_id = snapshot_id
            result.neo4j_snapshot_id = snapshot_id
            result.fuzzer_names = list(fuzzer_sources.keys())
            result.fuzzer_reach_count = self._count_reaches(snapshot_id)

        except Exception as e:
            result.error = str(e)
            result.error_phase = self._classify_error_phase(e)
            logger.error(
                "[%s] Pipeline failed at %s: %s",
                project_name,
                result.error_phase,
                e,
                exc_info=True,
            )
        finally:
            result.total_duration_sec = round(time.monotonic() - t0, 2)
            # Clean up output directory
            try:
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception:
                pass
            # Clean staging directories (Docker creates files as root)
            staging_dir = Path("/home/ze/zca-staging")
            for d in [
                staging_dir / f"output-{project_name}",
                staging_dir / f"svf-input-{project_name}",
                staging_dir / f"svf-output-{project_name}",
            ]:
                if d.exists():
                    try:
                        shutil.rmtree(d, ignore_errors=True)
                    except Exception:
                        # Files may be owned by root from Docker
                        subprocess.run(
                            ["sudo", "rm", "-rf", str(d)],
                            capture_output=True, timeout=10,
                        )

        return result

    # ── Joern pipeline ──────────────────────────────────────────────────────

    def _run_joern_pipeline(
        self,
        request: AutoAnalysisRequest,
        project_name: str,
        result: AutoAnalysisResult,
        t0: float,
    ) -> AutoAnalysisResult:
        """Run analysis using Joern backend (no compilation needed)."""
        logger.info("[%s] Using Joern backend (source-level analysis)", project_name)

        try:
            from z_code_analyzer.backends.joern_backend import JoernBackend
            from z_code_analyzer.project_configs import get_config

            config = get_config(project_name)

            # Resolve source directory
            source_dir = request.project_path
            if not source_dir:
                # Try to find in joern-workspace
                ws_path = Path(self._workspace_dir).parent / "joern-workspace" / project_name
                if ws_path.exists():
                    source_dir = str(ws_path)
                elif config and config.repo_url:
                    # Clone the repo
                    clone_dir = Path(self._workspace_dir) / f"joern-{project_name}"
                    clone_dir.mkdir(parents=True, exist_ok=True)
                    logger.info("[%s] Cloning %s...", project_name, config.repo_url)
                    subprocess.run(
                        ["git", "clone", "--depth=1", config.repo_url, str(clone_dir)],
                        capture_output=True, timeout=300,
                    )
                    # Copy fuzzer sources from oss-fuzz
                    if self._ossfuzz_path:
                        ossfuzz_proj = Path(self._ossfuzz_path) / "projects" / project_name
                        if ossfuzz_proj.exists():
                            for ext in ["*.c", "*.cc", "*.cpp"]:
                                for f in ossfuzz_proj.glob(ext):
                                    try:
                                        if "LLVMFuzzerTestOneInput" in f.read_text(errors="replace"):
                                            import shutil
                                            shutil.copy2(f, clone_dir)
                                    except Exception:
                                        pass
                    source_dir = str(clone_dir)

            if not source_dir or not Path(source_dir).exists():
                raise RuntimeError(f"No source directory found for {project_name}")

            # Run Joern analysis
            backend = JoernBackend()
            joern_t0 = time.monotonic()
            analysis = backend.analyze(source_dir, request.language or "cpp")
            result.svf_duration_sec = round(time.monotonic() - joern_t0, 2)
            result.function_count = len(analysis.functions)
            result.edge_count = len(analysis.edges)

            logger.info(
                "[%s] Joern complete: %d functions, %d edges",
                project_name, result.function_count, result.edge_count,
            )

            # Import to Neo4j
            repo_url = request.repo_url or (config.repo_url if config else "")
            result.repo_url = repo_url

            import_t0 = time.monotonic()
            snapshot_id = self._import_to_neo4j(
                project_name=project_name,
                repo_url=repo_url,
                version=request.version,
                analysis_result=analysis,
                fuzzer_sources={},  # Joern doesn't separate fuzzer sources
                fuzzer_calls={},
                language=request.language or "cpp",
                force=request.force,
            )
            result.import_duration_sec = round(time.monotonic() - import_t0, 2)

            result.success = True
            result.snapshot_id = snapshot_id
            result.neo4j_snapshot_id = snapshot_id

        except Exception as e:
            result.error = str(e)
            result.error_phase = "joern"
            logger.error("[%s] Joern pipeline failed: %s", project_name, e, exc_info=True)
        finally:
            result.total_duration_sec = round(time.monotonic() - t0, 2)

        return result

    # ── Phase 1: Resolve project ─────────────────────────────────────────────

    def _resolve_project(
        self, request: AutoAnalysisRequest, project_name: str
    ) -> tuple[str, str, str]:
        """Resolve Docker image, repo URL, and build.sh path.

        Returns (docker_image, repo_url, build_sh_docker_path).
        """
        docker_image = request.docker_image
        repo_url = request.repo_url
        build_sh_path = ""

        ossfuzz_path = request.ossfuzz_repo_path or self._ossfuzz_path
        project_dir = Path(ossfuzz_path) / "projects" / project_name if ossfuzz_path else None

        # Try to resolve from oss-fuzz metadata
        if project_dir and project_dir.is_dir():
            # Read project.yaml for repo_url
            yaml_file = project_dir / "project.yaml"
            if yaml_file.exists() and not repo_url:
                try:
                    import yaml
                    data = yaml.safe_load(yaml_file.read_text())
                    repo_url = str(data.get("main_repo", "") or "").strip()
                    # Fallback: extract from Dockerfile git clone
                    if not repo_url:
                        repo_url = self._extract_repo_from_dockerfile(
                            project_dir / "Dockerfile"
                        )
                    # Fallback: use homepage
                    if not repo_url:
                        repo_url = str(data.get("homepage", "") or "").strip()
                    # Last resort: synthetic URL
                    if not repo_url:
                        repo_url = f"https://github.com/oss-fuzz/{project_name}"
                except Exception:
                    pass

            # Use oss-fuzz Docker image
            if not docker_image:
                docker_image = f"gcr.io/oss-fuzz/{project_name}"

            # build.sh is copied into the image at /src/build.sh by oss-fuzz
            build_sh_path = "/src/build.sh"
        else:
            # No oss-fuzz metadata — use base-builder image
            if not docker_image:
                docker_image = "gcr.io/oss-fuzz-base/base-builder"

        # Ensure Docker image is available
        self._ensure_docker_image(docker_image)

        if not repo_url:
            repo_url = f"https://github.com/oss-fuzz/{project_name}"

        logger.info(
            "[%s] Resolved: image=%s, repo=%s",
            project_name,
            docker_image,
            repo_url,
        )
        return docker_image, repo_url, build_sh_path

    @staticmethod
    def _extract_repo_from_dockerfile(dockerfile: Path) -> str:
        """Extract first git clone URL from a Dockerfile."""
        if not dockerfile.exists():
            return ""
        try:
            content = dockerfile.read_text()
            m = re.search(
                r'git\s+clone\s+(?:--\S+\s+)*'
                r'(?:(?:-b|--branch)\s+\S+\s+)?'
                r'((?:https?|git)://\S+)',
                content,
            )
            if m:
                url = m.group(1).rstrip("\\").strip().strip("'\"").rstrip(".")
                return url
        except Exception:
            pass
        return ""

    def _ensure_docker_image(self, image: str) -> None:
        """Ensure Docker image exists locally, pull if needed."""
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True,
                timeout=10,
            )
            if result.returncode == 0:
                return
        except Exception:
            pass

        logger.info("Pulling Docker image: %s", image)
        try:
            subprocess.run(
                ["docker", "pull", image],
                check=True,
                capture_output=True,
                text=True,
                timeout=_DOCKER_PULL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Docker pull timed out for {image}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Docker pull failed for {image}: {e.stderr}")

    # ── Phase 2: Docker build ────────────────────────────────────────────────

    def _run_docker_build(
        self,
        project_name: str,
        docker_image: str,
        output_dir: str,
        build_sh_path: str,
        request: AutoAnalysisRequest,
    ) -> None:
        """Run auto-pipeline.sh inside Docker to produce bitcode."""
        svf_dir = Path(__file__).parent / "svf"
        pipeline_script = svf_dir / "auto-pipeline.sh"
        if not pipeline_script.exists():
            raise BitcodeError(f"Pipeline script not found: {pipeline_script}")

        # Snap Docker can't mount from /data2, so copy pipeline to a
        # Docker-accessible staging directory under /home.
        staging_dir = Path("/home/ze/zca-staging")
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_script = staging_dir / "auto-pipeline.sh"
        shutil.copy2(pipeline_script, staged_script)

        # Also stage the output dir if it's on /data2
        # Clean staging from previous runs to avoid stale data.
        # Docker creates files as root, so shutil.rmtree may fail — use sudo.
        output_staging = staging_dir / f"output-{project_name}"
        if output_staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(output_staging)],
                capture_output=True, timeout=30,
            )
        output_staging.mkdir(parents=True, exist_ok=True)

        container_name = f"zca-{project_name}-{uuid.uuid4().hex[:8]}"

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--memory", _DOCKER_BUILD_MEMORY,
            "--memory-swap", _DOCKER_BUILD_MEMORY,
            "-v", f"{output_staging}:/output",
            "-v", f"{staged_script}:/pipeline/auto-pipeline.sh:ro",
            "-e", f"PROJECT_NAME={project_name}",
            "-e", "SRC=/src",
            "-e", f"OUTPUT_DIR=/output",
            "-e", f"MAX_BUILD_TIME={_DOCKER_BUILD_TIMEOUT - 60}",
        ]

        if build_sh_path:
            cmd.extend(["-e", f"BUILD_SH_PATH={build_sh_path}"])

        if request.fuzzer_names:
            cmd.extend(["-e", f"FUZZER_NAMES={','.join(request.fuzzer_names)}"])

        cmd.extend([
            docker_image,
            "bash", "/pipeline/auto-pipeline.sh",
        ])

        logger.info("[%s] Docker cmd: %s", project_name, " ".join(cmd[:15]) + "...")

        log_path = Path(output_dir) / "docker_build.log"
        try:
            import threading
            with open(log_path, "w") as log_file:
                proc = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
                timed_out = threading.Event()

                def _watchdog():
                    """Kill container if build exceeds timeout."""
                    if not timed_out.wait(_DOCKER_BUILD_TIMEOUT):
                        return  # event set = build finished normally
                    # Timeout reached — kill the container
                    try:
                        subprocess.run(
                            ["docker", "kill", container_name],
                            capture_output=True, timeout=10,
                        )
                    except Exception:
                        pass
                    try:
                        proc.kill()
                    except Exception:
                        pass

                timer = threading.Thread(target=_watchdog, daemon=True)
                timer.start()
                build_start = time.monotonic()

                assert proc.stdout is not None
                for line in proc.stdout:
                    log_file.write(line)
                    log_file.flush()
                    stripped = line.rstrip()
                    if stripped.startswith("[") or stripped.startswith("===") or \
                            "SUCCESS" in stripped or "FATAL" in stripped:
                        logger.info("[%s][build] %s", project_name, stripped)
                    else:
                        logger.debug("[%s][build] %s", project_name, stripped)
                    # Check if we've exceeded timeout mid-stream
                    if time.monotonic() - build_start > _DOCKER_BUILD_TIMEOUT:
                        timed_out.set()
                        break

                timed_out.set()  # Signal watchdog to stop
                proc.wait(timeout=30)

            if time.monotonic() - build_start > _DOCKER_BUILD_TIMEOUT:
                raise BitcodeError(
                    f"Docker build timed out after {_DOCKER_BUILD_TIMEOUT}s for {project_name}"
                )
        except BitcodeError:
            raise
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
            raise BitcodeError(
                f"Docker build timed out after {_DOCKER_BUILD_TIMEOUT}s for {project_name}"
            )

        # Copy output files from staging back to workspace output_dir
        if output_staging != Path(output_dir):
            for f in output_staging.iterdir():
                dst = Path(output_dir) / f.name
                if f.is_dir():
                    shutil.copytree(f, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(f, dst)
            # Also copy the log if it was written inside staging
            staging_log = output_staging / "pipeline.log"
            if staging_log.exists():
                shutil.copy2(staging_log, Path(output_dir) / "pipeline.log")

        if proc.returncode != 0:
            # Read log tail for error context
            try:
                log_tail = log_path.read_text()[-3000:]
            except OSError:
                log_tail = "(no log)"
            raise BitcodeError(
                f"Docker build failed (rc={proc.returncode}) for {project_name}:\n"
                f"{log_tail}"
            )

    # ── Phase 4: SVF analysis ────────────────────────────────────────────────

    def _run_svf(
        self,
        project_name: str,
        bc_path: str,
        function_metas: list[FunctionMeta],
        language: str,
        output_dir: str,
    ) -> AnalysisResult:
        """Run SVF pointer analysis on library.bc."""
        t0 = time.monotonic()

        bc_resolved = str(Path(bc_path).resolve())
        bc_dir = str(Path(bc_resolved).parent)
        bc_name = Path(bc_resolved).name

        # Validate filename
        if not re.fullmatch(r"[\w.\-]+", bc_name):
            raise SVFError(f"Invalid bitcode filename: {bc_name}")

        container_name = f"zca-svf-{project_name}-{uuid.uuid4().hex[:8]}"
        svf_output = tempfile.mkdtemp(prefix="svf-", dir=output_dir)

        # Snap Docker can't mount from /data2, stage files under /home
        staging_dir = Path("/home/ze/zca-staging")
        staging_dir.mkdir(parents=True, exist_ok=True)
        svf_input_staging = staging_dir / f"svf-input-{project_name}"
        svf_input_staging.mkdir(parents=True, exist_ok=True)
        svf_output_staging = staging_dir / f"svf-output-{project_name}"
        svf_output_staging.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bc_resolved, svf_input_staging / bc_name)

        # Normalize IR to avoid SVF crashes:
        # - simplifycfg: fixes "exitBlock already set" assertion (multiple exit blocks)
        # - strip-debug: fixes "!dbg attachment points at wrong subprogram"
        opt_cmd = [
            "docker", "run", "--rm",
            "-v", f"{svf_input_staging}:/work",
            "svftools/svf",
            "/home/SVF-tools/SVF/llvm-18.1.0.obj/bin/opt",
            "-passes=simplifycfg", "-strip-debug",
            f"/work/{bc_name}", "-o", f"/work/optimized.bc",
        ]
        try:
            result = subprocess.run(opt_cmd, capture_output=True, timeout=300)
            optimized = svf_input_staging / "optimized.bc"
            if result.returncode == 0 and optimized.exists() and optimized.stat().st_size > 100:
                optimized.rename(svf_input_staging / bc_name)
                logger.info("[%s] Normalized bitcode for SVF (simplifycfg + strip-debug)", project_name)
        except Exception:
            pass  # If strip fails, try SVF with original bitcode

        # Ensure svftools/svf image is available
        self._ensure_docker_image("svftools/svf")

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--memory", _SVF_MEMORY,
            "--memory-swap", _SVF_MEMORY,
            "--workdir", "/output",
            "-v", f"{svf_input_staging}:/input:ro",
            "-v", f"{svf_output_staging}:/output",
            "svftools/svf",
            "wpa", "-ander", "-dump-callgraph", f"/input/{bc_name}",
        ]

        logger.info("[%s] SVF: %s", project_name, " ".join(cmd[:12]) + "...")

        # Stream SVF output to a log file instead of capturing in memory
        # (SVF can produce hundreds of MB of debug output)
        svf_log = Path(output_dir) / "svf.log"
        svf_returncode = -1
        svf_stderr_tail = ""
        try:
            with open(svf_log, "w") as log_f:
                proc = subprocess.Popen(
                    cmd,
                    stdout=log_f,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                # Read stderr in chunks to avoid unbounded memory
                stderr_lines: list[str] = []
                assert proc.stderr is not None
                for line in proc.stderr:
                    stderr_lines.append(line)
                    if len(stderr_lines) > 200:
                        stderr_lines = stderr_lines[-100:]
                proc.wait(timeout=_SVF_ANALYSIS_TIMEOUT)
                svf_returncode = proc.returncode
                svf_stderr_tail = "".join(stderr_lines[-50:])
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True,
                    timeout=10,
                )
            except Exception:
                pass
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
            raise SVFError(f"SVF timed out after {_SVF_ANALYSIS_TIMEOUT}s for {project_name}")

        # Copy SVF output from staging back to workspace
        for f in svf_output_staging.iterdir():
            dst = Path(svf_output) / f.name
            if f.is_dir():
                shutil.copytree(f, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(f, dst)
        # Clean up staging
        shutil.rmtree(svf_input_staging, ignore_errors=True)
        shutil.rmtree(svf_output_staging, ignore_errors=True)

        if svf_returncode != 0:
            logger.warning(
                "[%s] SVF stderr: %s",
                project_name,
                svf_stderr_tail[-2000:] if svf_stderr_tail else "",
            )

        # Find DOT files
        svf_out_path = Path(svf_output)
        dot_files = list(svf_out_path.glob("callgraph*.dot"))
        if not dot_files:
            all_files = [f.name for f in svf_out_path.iterdir()]
            raise SVFError(
                f"SVF produced no callgraph DOT for {project_name}. "
                f"Files: {all_files}, stderr: {svf_stderr_tail[-500:]}"
            )

        # Parse DOT files (streaming, line-by-line to save memory)
        dot_final = svf_out_path / "callgraph_final.dot"
        if not dot_final.exists():
            dot_final = dot_files[0]

        dot_initial = svf_out_path / "callgraph_initial.dot"

        nodes, final_adj = parse_svf_dot_file(dot_final)
        all_func_names = get_all_function_names(nodes)

        if dot_initial.exists():
            _, initial_adj = parse_svf_dot_file(dot_initial)
            typed_edges = get_typed_edge_list(initial_adj, final_adj)
        else:
            typed_edges = [(c, e, "direct") for c, es in final_adj.items() for e in es]

        # Build metadata lookup
        meta_by_name: dict[str, FunctionMeta] = {}
        for m in function_metas:
            if m.ir_name:
                meta_by_name[m.ir_name] = m
            if m.original_name and m.original_name != m.ir_name:
                meta_by_name[m.original_name] = m

        # Build FunctionRecord list
        functions: list[FunctionRecord] = []
        for func_name in sorted(all_func_names):
            meta = meta_by_name.get(func_name)
            functions.append(FunctionRecord(
                name=func_name,
                file_path=meta.file_path if meta else "",
                start_line=meta.line if meta else 0,
                end_line=meta.end_line if meta else 0,
                content=meta.content if meta else "",
                language=language,
                source_backend="svf",
            ))

        # Build CallEdge list
        edges: list[CallEdge] = []
        for caller, callee, ctype in typed_edges:
            caller_meta = meta_by_name.get(caller)
            callee_meta = meta_by_name.get(callee)
            edges.append(CallEdge(
                caller=caller,
                callee=callee,
                call_type=CallType.FPTR if ctype == "fptr" else CallType.DIRECT,
                caller_file=caller_meta.file_path if caller_meta else "",
                callee_file=callee_meta.file_path if callee_meta else "",
                source_backend="svf",
            ))

        duration = round(time.monotonic() - t0, 2)

        return AnalysisResult(
            functions=functions,
            edges=edges,
            language=language,
            backend="svf",
            analysis_duration_seconds=duration,
            metadata={
                "node_count": len(all_func_names),
                "edge_count": len(typed_edges),
                "fptr_edge_count": sum(1 for _, _, ct in typed_edges if ct == "fptr"),
            },
        )

    # ── Phase 5: Parse fuzzers ───────────────────────────────────────────────

    def _parse_fuzzers(
        self,
        project_name: str,
        output_dir: str,
        library_functions: set[str],
        request: AutoAnalysisRequest,
    ) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
        """Discover and parse fuzzer sources.

        Returns (fuzzer_sources, fuzzer_calls).

        Strategy:
        1. Read binary names from fuzzer_names.txt (populated by auto-pipeline.sh)
        2. Read source files from fuzzer_sources/ directory
        3. Filter obvious framework binaries (pattern-based)
        4. Match binaries to sources using strict prefix matching
        5. Keep only matched fuzzers; if NOTHING matched, fall back to source stems
        """
        fuzzer_sources: dict[str, list[str]] = {}
        fuzzer_out = Path(output_dir) / "fuzzer_sources"
        fuzzer_names_file = Path(output_dir) / "fuzzer_names.txt"

        # Read fuzzer binary names from metadata
        fuzzer_binary_names: list[str] = []
        if fuzzer_names_file.exists():
            fuzzer_binary_names = [
                n.strip() for n in fuzzer_names_file.read_text().splitlines()
                if n.strip()
            ]

        # If request specifies fuzzer names, use those
        if request.fuzzer_names:
            fuzzer_binary_names = request.fuzzer_names

        # Filter shared libraries and obvious framework binaries
        before_count = len(fuzzer_binary_names)
        fuzzer_binary_names = [
            n for n in fuzzer_binary_names
            if not n.endswith(".so") and ".so." not in n
            and not _is_framework_binary(n)
        ]
        if before_count != len(fuzzer_binary_names):
            logger.info(
                "[%s] Filtered %d framework/non-fuzzer binaries, %d remain",
                project_name,
                before_count - len(fuzzer_binary_names),
                len(fuzzer_binary_names),
            )

        # Find fuzzer source files
        if fuzzer_out.is_dir():
            fuzzer_src_files = [
                f for f in fuzzer_out.iterdir()
                if f.suffix in (".c", ".cc", ".cpp", ".cxx")
            ]
        else:
            fuzzer_src_files = []

        if fuzzer_binary_names and fuzzer_src_files:
            # Match binaries to source files using strict prefix matching
            matched: dict[str, list[str]] = {}
            unmatched: list[str] = []

            for fname in fuzzer_binary_names:
                matched_sources: list[str] = []
                for sf in fuzzer_src_files:
                    if _fuzzer_name_matches(fname, sf.stem):
                        matched_sources.append(str(sf))
                if matched_sources:
                    matched[fname] = matched_sources
                else:
                    unmatched.append(fname)

            if matched:
                # Some binaries matched — use those, skip unmatched
                fuzzer_sources = matched
                if unmatched:
                    logger.info(
                        "[%s] Matched %d fuzzers to sources, "
                        "skipped %d unmatched binaries",
                        project_name, len(matched), len(unmatched),
                    )
            else:
                # NOTHING matched — naming convention mismatch.
                # Use source file stems as fuzzer names instead of binary names.
                logger.warning(
                    "[%s] No fuzzer binaries matched source files — "
                    "using %d source files as fuzzer entries",
                    project_name, len(fuzzer_src_files),
                )
                for sf in fuzzer_src_files:
                    fuzzer_sources[sf.stem] = [str(sf)]
        elif fuzzer_src_files:
            # No fuzzer binary names — create entries from source files
            for sf in fuzzer_src_files:
                fuzzer_sources[sf.stem] = [str(sf)]
        elif fuzzer_binary_names:
            # No source files — create empty entries
            for fname in fuzzer_binary_names:
                fuzzer_sources[fname] = []

        # Parse fuzzer calls using FuzzerEntryParser
        fuzzer_calls: dict[str, list[str]] = {}
        if fuzzer_sources:
            parser = FuzzerEntryParser()

            # Build expanded library function set to handle prefixed names.
            # e.g., OSS_FUZZ_png_create_read_struct → also match png_create_read_struct
            # Strips leading UPPERCASE_ segments (common build-time symbol prefixes).
            alias_to_canonical: dict[str, str] = {}
            for func_name in library_functions:
                alias_to_canonical[func_name] = func_name
                remaining = func_name
                while True:
                    idx = remaining.find("_")
                    if idx == -1:
                        break
                    prefix_part = remaining[:idx]
                    if prefix_part.isupper() and len(prefix_part) >= 2:
                        remaining = remaining[idx + 1:]
                        if remaining and remaining not in alias_to_canonical:
                            alias_to_canonical[remaining] = func_name
                    else:
                        break
            expanded_library = set(alias_to_canonical.keys())

            if len(expanded_library) > len(library_functions):
                logger.info(
                    "[%s] Expanded library functions: %d → %d (prefix aliases)",
                    project_name,
                    len(library_functions),
                    len(expanded_library),
                )

            logger.info(
                "[%s] Library functions available: %d (sample: %s)",
                project_name,
                len(library_functions),
                sorted(library_functions)[:5],
            )
            for fuzzer_name, source_files in fuzzer_sources.items():
                if not source_files:
                    fuzzer_calls[fuzzer_name] = []
                    continue
                # Check source files exist
                for sf in source_files:
                    if not Path(sf).exists():
                        logger.warning(
                            "[%s] Fuzzer source file NOT found: %s",
                            project_name, sf,
                        )
                single_map = {fuzzer_name: source_files}
                calls = parser.parse(
                    single_map,
                    expanded_library,
                    str(fuzzer_out) if fuzzer_out.is_dir() else output_dir,
                )
                # Map matched aliases back to canonical SVF names
                raw_calls = calls.get(fuzzer_name, [])
                canonical_calls = sorted(set(
                    alias_to_canonical.get(c, c) for c in raw_calls
                ))
                fuzzer_calls[fuzzer_name] = canonical_calls
                if not fuzzer_calls[fuzzer_name]:
                    logger.warning(
                        "[%s] Fuzzer '%s' has 0 matching library calls (sources: %s)",
                        project_name, fuzzer_name,
                        [Path(sf).name for sf in source_files],
                    )

        logger.info(
            "[%s] Fuzzers: %d found, %d with source, %d lib calls total",
            project_name,
            len(fuzzer_sources),
            sum(1 for v in fuzzer_sources.values() if v),
            sum(len(v) for v in fuzzer_calls.values()),
        )

        return fuzzer_sources, fuzzer_calls

    # ── Phase 6: Import to Neo4j ─────────────────────────────────────────────

    def _import_to_neo4j(
        self,
        project_name: str,
        repo_url: str,
        version: str,
        analysis_result: AnalysisResult,
        fuzzer_sources: dict[str, list[str]],
        fuzzer_calls: dict[str, list[str]],
        language: str,
        force: bool = False,
    ) -> str:
        """Import analysis results into Neo4j and create PostgreSQL snapshot."""
        # Create snapshot record
        import asyncio

        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop and loop.is_running():
            # Already in an async context — run synchronously via thread
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                snapshot_doc = pool.submit(
                    self._acquire_snapshot_sync, repo_url, version
                ).result()
        else:
            snapshot_doc = asyncio.run(
                self._sm.acquire_or_wait(repo_url, version, "svf")
            )

        if snapshot_doc and snapshot_doc.status == "completed" and not force:
            # Check if Neo4j actually has data for this snapshot
            neo4j_has_data = self._neo4j_has_snapshot(str(snapshot_doc.id))
            if neo4j_has_data:
                logger.info("[%s] Snapshot already exists with data: %s", project_name, snapshot_doc.id)
                return str(snapshot_doc.id)
            logger.warning(
                "[%s] Snapshot %s marked completed in PG but missing from Neo4j — re-importing",
                project_name, snapshot_doc.id,
            )
        elif snapshot_doc and snapshot_doc.status == "completed" and force:
            logger.info("[%s] Force re-import for snapshot %s", project_name, snapshot_doc.id)

        if not snapshot_doc:
            raise RuntimeError(
                f"Failed to acquire snapshot lock for {project_name}"
            )

        snapshot_id = str(snapshot_doc.id)

        try:
            # Clean any partial data
            self._gs.delete_snapshot(snapshot_id)

            # Create snapshot node
            self._gs.create_snapshot_node(
                snapshot_id, repo_url, version, "svf"
            )

            # Import functions and edges
            func_count = self._gs.import_functions(
                snapshot_id, analysis_result.functions
            )
            edge_count = self._gs.import_edges(
                snapshot_id, analysis_result.edges
            )

            # Import fuzzers
            fuzzer_infos = self._build_fuzzer_infos(fuzzer_sources, fuzzer_calls)
            self._gs.import_fuzzers(snapshot_id, fuzzer_infos)

            # Compute REACHES
            reaches = self._compute_reaches(snapshot_id, fuzzer_infos)
            self._gs.import_reaches(snapshot_id, reaches)

            # Mark snapshot as completed
            fuzzer_names = [fi.name for fi in fuzzer_infos]
            self._sm.mark_completed(
                snapshot_id,
                func_count,
                edge_count,
                fuzzer_names,
                analysis_duration_sec=analysis_result.analysis_duration_seconds,
                language=language,
            )

            logger.info(
                "[%s] Neo4j import complete: %d functions, %d edges, "
                "%d reaches, %d fuzzers",
                project_name,
                func_count,
                edge_count,
                len(reaches),
                len(fuzzer_names),
            )
            return snapshot_id

        except Exception as e:
            try:
                self._sm.mark_failed(snapshot_id, str(e))
            except Exception:
                pass
            try:
                self._gs.delete_snapshot(snapshot_id)
            except Exception:
                pass
            raise

    def _acquire_snapshot_sync(self, repo_url: str, version: str):
        """Synchronous wrapper for acquire_or_wait."""
        import asyncio
        return asyncio.run(
            self._sm.acquire_or_wait(repo_url, version, "svf")
        )

    def _neo4j_has_snapshot(self, snapshot_id: str) -> bool:
        """Check if Neo4j actually has data for this snapshot."""
        try:
            with self._gs._session() as session:
                result = session.run(
                    "MATCH (f:Function {snapshot_id: $sid}) RETURN count(f) AS cnt LIMIT 1",
                    sid=snapshot_id,
                )
                record = result.single()
                return record is not None and record["cnt"] > 0
        except Exception:
            return False

    @staticmethod
    def _build_fuzzer_infos(
        fuzzer_sources: dict[str, list[str]],
        fuzzer_calls: dict[str, list[str]],
    ) -> list[FuzzerInfo]:
        """Build FuzzerInfo list from parsed data."""
        infos: list[FuzzerInfo] = []
        for name, source_files in fuzzer_sources.items():
            infos.append(FuzzerInfo(
                name=name,
                entry_function="LLVMFuzzerTestOneInput",
                files=[{"path": f, "source": "auto"} for f in source_files],
                called_library_functions=fuzzer_calls.get(name, []),
            ))
        return infos

    def _compute_reaches(
        self,
        snapshot_id: str,
        fuzzer_infos: list[FuzzerInfo],
    ) -> list[dict]:
        """BFS reachability from each fuzzer entry.

        Uses the Fuzzer-[:ENTRY]->Function relationship to find entry points,
        then traverses CALLS edges to find all reachable functions.
        """
        reaches: list[dict] = []
        for fuzzer in fuzzer_infos:
            try:
                with self._gs._session() as session:
                    result = session.run(
                        f"""
                        MATCH (fz:Fuzzer {{snapshot_id: $sid, name: $fuzzer_name}})
                              -[:ENTRY]->(entry:Function)
                        MATCH (f:Function {{snapshot_id: $sid}})
                        WHERE f <> entry
                        MATCH p = shortestPath(
                            (entry)-[:CALLS*..{_MAX_REACH_DEPTH}]->(f)
                        )
                        RETURN f.name AS func_name, f.file_path AS file_path,
                               length(p) AS depth
                        LIMIT 10000
                        """,
                        sid=snapshot_id,
                        fuzzer_name=fuzzer.name,
                    )
                    for row in result:
                        reaches.append({
                            "fuzzer_name": fuzzer.name,
                            "function_name": row["func_name"],
                            "file_path": row["file_path"],
                            "depth": row["depth"],
                        })
            except Exception as e:
                logger.warning(
                    "REACHES computation failed for fuzzer %s: %s",
                    fuzzer.name,
                    e,
                )
        return reaches

    def _count_reaches(self, snapshot_id: str) -> int:
        """Count total REACHES edges for a snapshot."""
        try:
            with self._gs._session() as session:
                result = session.run(
                    "MATCH (fz:Fuzzer {snapshot_id: $sid})-[r:REACHES]->() "
                    "RETURN count(r) AS cnt",
                    sid=snapshot_id,
                )
                record = result.single()
                return record["cnt"] if record else 0
        except Exception:
            return 0

    @staticmethod
    def _extract_project_name(repo_url: str) -> str:
        """Extract project name from repo URL."""
        if not repo_url:
            return "unknown"
        name = repo_url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name.lower()

    @staticmethod
    def _classify_error_phase(exc: Exception) -> str:
        """Classify which phase an error occurred in."""
        msg = str(exc).lower()
        if isinstance(exc, BitcodeError) or "bitcode" in msg or "docker build" in msg:
            return "build"
        if isinstance(exc, SVFError) or "svf" in msg or "callgraph" in msg:
            return "svf"
        if "neo4j" in msg or "import" in msg:
            return "import"
        if "snapshot" in msg:
            return "snapshot"
        if "docker pull" in msg or "image" in msg:
            return "docker"
        return "unknown"


def _human_size(size_bytes: int) -> str:
    """Convert bytes to human-readable size."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"

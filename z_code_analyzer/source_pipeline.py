"""Source-based analysis pipeline — full call graph from git repo source code.

Unlike the oss-fuzz pipeline (which only analyzes what fuzzers compile),
this pipeline compiles ALL source files in a repo to produce a complete
call graph.

Flow:
1. Clone repo (or use local path)
2. Build all C/C++ sources to LLVM bitcode inside Docker
3. Run SVF pointer analysis
4. Parse DOT output
5. Import to Neo4j + PostgreSQL
"""

from __future__ import annotations

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
)
from z_code_analyzer.build.bitcode import BitcodeGenerator
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

# Timeouts
_BUILD_TIMEOUT = 900      # 15 min for source build
_SVF_TIMEOUT = 600        # 10 min for SVF
_DOCKER_PULL_TIMEOUT = 600

# Docker memory limits
_BUILD_MEMORY = "8g"
_SVF_MEMORY = "16g"

@dataclass
class SourceAnalysisRequest:
    """Request for source-based analysis."""
    repo_url: str = ""
    project_path: str = ""       # local path (skip clone)
    project_name: str = ""       # override auto-detected name
    version: str = "HEAD"
    branch: str = ""
    language: str = ""
    force: bool = False


@dataclass
class SourceAnalysisResult:
    """Result from source-based analysis."""
    success: bool = False
    project_name: str = ""
    repo_url: str = ""
    version: str = ""
    snapshot_id: str = ""
    neo4j_snapshot_id: str = ""
    neo4j_uri: str = ""
    function_count: int = 0
    internal_function_count: int = 0
    external_function_count: int = 0
    edge_count: int = 0
    build_duration_sec: float = 0
    svf_duration_sec: float = 0
    import_duration_sec: float = 0
    total_duration_sec: float = 0
    error: str = ""
    error_phase: str = ""

    def summary(self) -> str:
        lines = [f"\n{'='*60}"]
        if self.success:
            lines.append(f"  Source Analysis: {self.project_name} — SUCCESS")
        else:
            lines.append(f"  Source Analysis: {self.project_name} — FAILED")
            lines.append(f"  Error ({self.error_phase}): {self.error}")
        lines.append(f"{'='*60}")
        lines.append(f"  Functions: {self.function_count} "
                      f"({self.internal_function_count} internal, "
                      f"{self.external_function_count} external)")
        lines.append(f"  Call edges: {self.edge_count}")
        lines.append(f"  Duration: {self.total_duration_sec}s "
                      f"(build={self.build_duration_sec}s, "
                      f"svf={self.svf_duration_sec}s, "
                      f"import={self.import_duration_sec}s)")
        if self.snapshot_id:
            lines.append(f"  Snapshot: {self.snapshot_id}")
            lines.append(f"  Neo4j: {self.neo4j_uri}")
        lines.append(f"{'='*60}")
        return "\n".join(lines)


class SourcePipeline:
    """Pipeline for full source-code analysis."""

    def __init__(
        self,
        snapshot_manager: SnapshotManager,
        graph_store: GraphStore,
        neo4j_uri: str = "",
        workspace_dir: str = "",
    ) -> None:
        self._sm = snapshot_manager
        self._gs = graph_store
        self._neo4j_uri = neo4j_uri
        self._workspace_dir = workspace_dir or str(Path.cwd() / "workspace")
        Path(self._workspace_dir).mkdir(parents=True, exist_ok=True)

    def run(self, request: SourceAnalysisRequest) -> SourceAnalysisResult:
        """Execute the full source analysis pipeline."""
        t0 = time.monotonic()
        project_name = request.project_name or self._extract_project_name(
            request.repo_url or request.project_path
        )
        result = SourceAnalysisResult(
            project_name=project_name,
            repo_url=request.repo_url,
            version=request.version,
            neo4j_uri=self._neo4j_uri,
        )

        output_dir = tempfile.mkdtemp(
            prefix=f"source-{project_name}-",
            dir=self._workspace_dir,
        )

        try:
            # Phase 1: Build bitcode from source
            logger.info("[%s] Phase 1: Building bitcode from source...", project_name)
            build_t0 = time.monotonic()
            self._run_source_build(
                project_name=project_name,
                request=request,
                output_dir=output_dir,
            )
            result.build_duration_sec = round(time.monotonic() - build_t0, 2)

            bc_path = Path(output_dir) / "library.bc"
            if not bc_path.exists():
                raise BitcodeError(f"library.bc not produced in {output_dir}")
            logger.info(
                "[%s] Bitcode ready: %s (%s)",
                project_name, bc_path,
                _human_size(bc_path.stat().st_size),
            )

            # Phase 2: Parse .ll for function metadata
            logger.info("[%s] Phase 2: Parsing function metadata...", project_name)
            ll_path = Path(output_dir) / "library.ll"
            function_metas: list[FunctionMeta] = []
            if ll_path.exists() and ll_path.stat().st_size > 0:
                function_metas = BitcodeGenerator._parse_ll_debug_info(
                    ll_path, request.project_path or project_name,
                    docker_mount_name=project_name,
                )
                logger.info(
                    "[%s] Extracted %d function metas from .ll",
                    project_name, len(function_metas),
                )

            # Phase 3: SVF analysis
            logger.info("[%s] Phase 3: Running SVF pointer analysis...", project_name)
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
            result.internal_function_count = analysis_result.metadata.get("internal_count", 0)
            result.external_function_count = analysis_result.metadata.get("external_count", 0)
            result.edge_count = len(analysis_result.edges)
            logger.info(
                "[%s] SVF complete: %d functions (%d internal), %d edges",
                project_name,
                result.function_count,
                result.internal_function_count,
                result.edge_count,
            )

            # Phase 4: Import to Neo4j
            logger.info("[%s] Phase 4: Importing to Neo4j...", project_name)
            import_t0 = time.monotonic()
            repo_url = request.repo_url or f"source://{project_name}"
            snapshot_id = self._import_to_neo4j(
                project_name=project_name,
                repo_url=repo_url,
                version=request.version,
                analysis_result=analysis_result,
                language=language,
                force=request.force,
            )
            result.import_duration_sec = round(time.monotonic() - import_t0, 2)

            # Quality gate: must have meaningful analysis results
            _fn_useful = result.function_count >= 10 and result.edge_count > 0
            _int_useful = result.internal_function_count >= 5
            if not _fn_useful and not _int_useful:
                raise BitcodeError(
                    f"Too few functions ({result.function_count} total, "
                    f"{result.internal_function_count} internal, "
                    f"{result.edge_count} edges) — "
                    f"build likely failed or project has no compilable source"
                )

            result.success = True
            result.snapshot_id = snapshot_id
            result.neo4j_snapshot_id = snapshot_id

        except Exception as e:
            result.error = str(e)
            result.error_phase = self._classify_error_phase(e)
            logger.error(
                "[%s] Pipeline failed at %s: %s",
                project_name, result.error_phase, e,
                exc_info=True,
            )
        finally:
            result.total_duration_sec = round(time.monotonic() - t0, 2)
            try:
                shutil.rmtree(output_dir, ignore_errors=True)
            except Exception:
                pass
            # Clean staging
            staging_dir = Path("/home/ze/zca-staging")
            for d in [
                staging_dir / f"source-output-{project_name}",
                staging_dir / f"svf-input-{project_name}",
                staging_dir / f"svf-output-{project_name}",
            ]:
                if d.exists():
                    try:
                        shutil.rmtree(d, ignore_errors=True)
                    except Exception:
                        subprocess.run(
                            ["sudo", "rm", "-rf", str(d)],
                            capture_output=True, timeout=10,
                        )

        return result

    # ── Phase 1: Source build ────────────────────────────────────────────────

    def _run_source_build(
        self,
        project_name: str,
        request: SourceAnalysisRequest,
        output_dir: str,
    ) -> None:
        """Build all source files to bitcode inside Docker."""
        svf_dir = Path(__file__).parent / "svf"
        build_script = svf_dir / "source-build.sh"
        if not build_script.exists():
            raise BitcodeError(f"Source build script not found: {build_script}")

        # Stage files for Docker
        staging_dir = Path("/home/ze/zca-staging")
        staging_dir.mkdir(parents=True, exist_ok=True)
        staged_script = staging_dir / "source-build.sh"
        shutil.copy2(build_script, staged_script)

        output_staging = staging_dir / f"source-output-{project_name}"
        if output_staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(output_staging)],
                capture_output=True, timeout=30,
            )
        output_staging.mkdir(parents=True, exist_ok=True)

        container_name = f"zca-src-{project_name}-{uuid.uuid4().hex[:8]}"

        # Use pre-built image with LLVM toolchain; fall back to ubuntu:22.04
        docker_image = "zca-source-base:latest"
        try:
            r = subprocess.run(
                ["docker", "image", "inspect", docker_image],
                capture_output=True, timeout=5,
            )
            if r.returncode != 0:
                docker_image = "ubuntu:22.04"
        except Exception:
            docker_image = "ubuntu:22.04"
        self._ensure_docker_image(docker_image)

        cmd = [
            "docker", "run", "--rm",
            "--name", container_name,
            "--memory", _BUILD_MEMORY,
            "--memory-swap", _BUILD_MEMORY,
            "-v", f"{output_staging}:/output",
            "-v", f"{staged_script}:/pipeline/source-build.sh:ro",
            "-e", f"PROJECT_NAME={project_name}",
            "-e", f"OUTPUT_DIR=/output",
            "-e", f"MAX_BUILD_TIME={_BUILD_TIMEOUT - 60}",
        ]

        # Pass version/ref info — REPO_REF supports tags, commit hashes, PR refs
        # version takes priority; branch is fallback
        effective_ref = request.version if request.version and request.version != "HEAD" else request.branch
        if effective_ref:
            cmd.extend(["-e", f"REPO_REF={effective_ref}"])

        # Mount source or pass repo URL
        if request.project_path and Path(request.project_path).is_dir():
            source_staging = staging_dir / f"source-code-{project_name}"
            if source_staging.exists():
                subprocess.run(
                    ["sudo", "rm", "-rf", str(source_staging)],
                    capture_output=True, timeout=30,
                )
            shutil.copytree(request.project_path, source_staging)
            cmd.extend([
                "-v", f"{source_staging}:/source:ro",
                "-e", f"SOURCE_DIR=/source",
            ])
        else:
            cmd.extend(["-e", f"REPO_URL={request.repo_url}"])

        cmd.extend([
            docker_image,
            "bash", "/pipeline/source-build.sh",
        ])

        logger.info("[%s] Docker cmd: %s", project_name, " ".join(cmd[:15]) + "...")

        log_path = Path(output_dir) / "docker_build.log"
        import threading
        with open(log_path, "w") as log_file:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
            )
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
                if time.monotonic() - build_start > _BUILD_TIMEOUT:
                    break

            proc.wait(timeout=30)

        if time.monotonic() - build_start > _BUILD_TIMEOUT:
            try:
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True, timeout=10,
                )
            except Exception:
                pass
            raise BitcodeError(
                f"Source build timed out after {_BUILD_TIMEOUT}s for {project_name}"
            )

        # Copy from staging (may not exist if Docker crashed or was killed)
        if output_staging != Path(output_dir) and output_staging.exists():
            for f in output_staging.iterdir():
                dst = Path(output_dir) / f.name
                if f.is_dir():
                    shutil.copytree(f, dst, dirs_exist_ok=True)
                else:
                    shutil.copy2(f, dst)

        if proc.returncode != 0:
            try:
                log_tail = log_path.read_text()[-3000:]
            except OSError:
                log_tail = "(no log)"
            raise BitcodeError(
                f"Source build failed (rc={proc.returncode}) for {project_name}:\n"
                f"{log_tail}"
            )

    # ── Phase 3: SVF analysis ────────────────────────────────────────────────

    def _run_svf(
        self,
        project_name: str,
        bc_path: str,
        function_metas: list[FunctionMeta],
        language: str,
        output_dir: str,
    ) -> AnalysisResult:
        """Run SVF pointer analysis on library.bc."""
        bc_resolved = str(Path(bc_path).resolve())
        bc_name = Path(bc_resolved).name

        if not re.fullmatch(r"[\w.\-]+", bc_name):
            raise SVFError(f"Invalid bitcode filename: {bc_name}")

        container_name = f"zca-svf-{project_name}-{uuid.uuid4().hex[:8]}"
        svf_output = tempfile.mkdtemp(prefix="svf-", dir=output_dir)

        # Stage for Docker
        staging_dir = Path("/home/ze/zca-staging")
        staging_dir.mkdir(parents=True, exist_ok=True)
        svf_input_staging = staging_dir / f"svf-input-{project_name}"
        if svf_input_staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(svf_input_staging)],
                capture_output=True, timeout=30,
            )
        svf_input_staging.mkdir(parents=True, exist_ok=True)
        svf_output_staging = staging_dir / f"svf-output-{project_name}"
        if svf_output_staging.exists():
            subprocess.run(
                ["sudo", "rm", "-rf", str(svf_output_staging)],
                capture_output=True, timeout=30,
            )
        svf_output_staging.mkdir(parents=True, exist_ok=True)
        shutil.copy2(bc_resolved, svf_input_staging / bc_name)

        # Normalize IR
        opt_cmd = [
            "docker", "run", "--rm",
            "-v", f"{svf_input_staging}:/work",
            "svftools/svf",
            "/home/SVF-tools/SVF/llvm-18.1.0.obj/bin/opt",
            "-passes=simplifycfg", "-strip-debug",
            f"/work/{bc_name}", "-o", "/work/optimized.bc",
        ]
        try:
            result = subprocess.run(opt_cmd, capture_output=True, timeout=300)
            optimized = svf_input_staging / "optimized.bc"
            if result.returncode == 0 and optimized.exists() and optimized.stat().st_size > 100:
                optimized.rename(svf_input_staging / bc_name)
                logger.info("[%s] Normalized bitcode (simplifycfg + strip-debug)", project_name)
        except Exception:
            pass

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

        svf_log = Path(output_dir) / "svf.log"
        svf_stderr_tail = ""
        try:
            with open(svf_log, "w") as log_f:
                proc = subprocess.Popen(
                    cmd, stdout=log_f, stderr=subprocess.PIPE, text=True,
                )
                stderr_lines: list[str] = []
                assert proc.stderr is not None
                for line in proc.stderr:
                    stderr_lines.append(line)
                    if len(stderr_lines) > 200:
                        stderr_lines = stderr_lines[-100:]
                proc.wait(timeout=_SVF_TIMEOUT)
                svf_stderr_tail = "".join(stderr_lines[-50:])
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(
                    ["docker", "kill", container_name],
                    capture_output=True, timeout=10,
                )
            except Exception:
                pass
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception:
                pass
            raise SVFError(f"SVF timed out after {_SVF_TIMEOUT}s for {project_name}")

        # Copy output
        for f in svf_output_staging.iterdir():
            dst = Path(svf_output) / f.name
            if f.is_dir():
                shutil.copytree(f, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(f, dst)
        shutil.rmtree(svf_input_staging, ignore_errors=True)
        shutil.rmtree(svf_output_staging, ignore_errors=True)

        if proc.returncode != 0:
            logger.warning("[%s] SVF stderr: %s", project_name, svf_stderr_tail[-2000:])

        # Parse DOT
        svf_out_path = Path(svf_output)
        dot_files = list(svf_out_path.glob("callgraph*.dot"))
        if not dot_files:
            all_files = [f.name for f in svf_out_path.iterdir()]
            raise SVFError(
                f"SVF produced no callgraph DOT for {project_name}. "
                f"Files: {all_files}, stderr: {svf_stderr_tail[-500:]}"
            )

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
        # External functions (libc, zlib, etc.) will have no file_path/content
        # since they weren't compiled from source — GraphStore detects this
        # automatically via `not f.file_path and not f.content`.
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
                source_backend="svf-source",
            ))

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
                source_backend="svf-source",
            ))

        return AnalysisResult(
            functions=functions,
            edges=edges,
            language=language,
            backend="svf-source",
            analysis_duration_seconds=0,
            metadata={
                "node_count": len(all_func_names),
                "edge_count": len(typed_edges),
                "internal_count": sum(1 for f in functions if f.file_path),
                "external_count": sum(1 for f in functions if not f.file_path),
                "fptr_edge_count": sum(1 for _, _, ct in typed_edges if ct == "fptr"),
            },
        )

    # ── Phase 4: Import to Neo4j ─────────────────────────────────────────────

    def _import_to_neo4j(
        self,
        project_name: str,
        repo_url: str,
        version: str,
        analysis_result: AnalysisResult,
        language: str,
        force: bool = False,
    ) -> str:
        """Import analysis results into Neo4j and create PostgreSQL snapshot."""
        import asyncio

        loop = None
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            pass

        if loop and loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                snapshot_doc = pool.submit(
                    self._acquire_snapshot_sync, repo_url, version
                ).result()
        else:
            snapshot_doc = asyncio.run(
                self._sm.acquire_or_wait(repo_url, version, "svf-source")
            )

        if snapshot_doc and snapshot_doc.status == "completed" and not force:
            neo4j_has_data = self._neo4j_has_snapshot(str(snapshot_doc.id))
            if neo4j_has_data:
                logger.info("[%s] Snapshot already exists: %s", project_name, snapshot_doc.id)
                return str(snapshot_doc.id)
            logger.warning(
                "[%s] Snapshot %s completed in PG but missing from Neo4j — re-importing",
                project_name, snapshot_doc.id,
            )
        elif snapshot_doc and snapshot_doc.status == "completed" and force:
            logger.info("[%s] Force re-import for snapshot %s", project_name, snapshot_doc.id)

        if not snapshot_doc:
            raise RuntimeError(f"Failed to acquire snapshot lock for {project_name}")

        snapshot_id = str(snapshot_doc.id)

        try:
            self._gs.delete_snapshot(snapshot_id)
            self._gs.create_snapshot_node(snapshot_id, repo_url, version, "svf-source")

            func_count = self._gs.import_functions(
                snapshot_id, analysis_result.functions,
            )
            edge_count = self._gs.import_edges(snapshot_id, analysis_result.edges)

            # No fuzzers in source mode — this is a pure call graph
            self._sm.mark_completed(
                snapshot_id,
                func_count,
                edge_count,
                [],  # no fuzzers
                analysis_duration_sec=analysis_result.analysis_duration_seconds,
                language=language,
            )

            logger.info(
                "[%s] Neo4j import complete: %d functions, %d edges",
                project_name, func_count, edge_count,
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
        import asyncio
        return asyncio.run(
            self._sm.acquire_or_wait(repo_url, version, "svf-source")
        )

    def _neo4j_has_snapshot(self, snapshot_id: str) -> bool:
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

    def _ensure_docker_image(self, image: str) -> None:
        try:
            result = subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True, timeout=10,
            )
            if result.returncode == 0:
                return
        except Exception:
            pass
        logger.info("Pulling Docker image: %s", image)
        try:
            subprocess.run(
                ["docker", "pull", image],
                check=True, capture_output=True, text=True,
                timeout=_DOCKER_PULL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Docker pull timed out for {image}")
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Docker pull failed for {image}: {e.stderr}")

    @staticmethod
    def _extract_project_name(path_or_url: str) -> str:
        if not path_or_url:
            return "unknown"
        name = path_or_url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name.lower().replace(" ", "-")

    @staticmethod
    def _classify_error_phase(exc: Exception) -> str:
        msg = str(exc).lower()
        if isinstance(exc, BitcodeError) or "bitcode" in msg or "build" in msg:
            return "build"
        if isinstance(exc, SVFError) or "svf" in msg or "callgraph" in msg:
            return "svf"
        if "neo4j" in msg or "import" in msg:
            return "import"
        if "snapshot" in msg:
            return "snapshot"
        return "unknown"


def _human_size(size_bytes: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f}{unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f}TB"

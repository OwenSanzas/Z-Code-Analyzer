"""CLI entry point for standalone usage: z-analyze.

Subcommands:
    z-analyze create-work -o work.json    # Generate work order template
    z-analyze run work.json               # Execute analysis from work order
    z-analyze probe /path/to/project      # Quick project probe (Phase 1 only)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import click

# Default connection strings (overridable via env vars)
_DEFAULT_NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
_DEFAULT_PG_URL = os.environ.get("ZCA_DATABASE_URL", "postgresql://localhost/z_code_analyzer")


def _parse_neo4j_auth() -> tuple[str, str] | None:
    """Parse Neo4j auth from NEO4J_AUTH env var (doc: appendix-b).

    Supported formats:
        NEO4J_AUTH=none             → no auth (returns None)
        NEO4J_AUTH=neo4j:password   → (neo4j, password)
        NEO4J_USER + NEO4J_PASSWORD → fallback to separate env vars
    """
    neo4j_auth = os.environ.get("NEO4J_AUTH")
    if neo4j_auth is not None:
        if neo4j_auth.lower() == "none":
            return None
        if ":" in neo4j_auth:
            user, password = neo4j_auth.split(":", 1)
            return (user, password)
        # Malformed — treat as no-auth with a warning
        logging.getLogger(__name__).warning(
            "NEO4J_AUTH has unrecognized format"
            " (expected 'none' or 'user:password'), treating as no-auth"
        )
        return None
    # Fallback: separate env vars (backward compat)
    user = os.environ.get("NEO4J_USER")
    password = os.environ.get("NEO4J_PASSWORD")
    if user and password:
        return (user, password)
    return None  # default: no auth


def _workspace_dir() -> Path:
    """Return the workspace directory, creating it if needed."""
    ws = Path.cwd() / "workspace"
    ws.mkdir(exist_ok=True)
    return ws


def _auto_clone(repo_url: str, version: str) -> str | None:
    """Clone a repo to a workspace subdirectory and checkout the given version."""
    tmpdir = tempfile.mkdtemp(prefix="clone-", dir=_workspace_dir())
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", "--branch", version, repo_url, tmpdir],
            check=True,
            capture_output=True,
            text=True,
        )
        return tmpdir
    except subprocess.CalledProcessError:
        # --branch may fail for commit hashes; try full clone + checkout
        # First remove the partially-created directory contents
        import shutil

        shutil.rmtree(tmpdir, ignore_errors=True)
        os.makedirs(tmpdir, exist_ok=True)
        try:
            subprocess.run(
                ["git", "clone", repo_url, tmpdir],
                check=True,
                capture_output=True,
                text=True,
            )
            subprocess.run(
                ["git", "-C", tmpdir, "checkout", version],
                check=True,
                capture_output=True,
                text=True,
            )
            return tmpdir
        except subprocess.CalledProcessError as e:
            click.echo(f"Git clone/checkout failed: {e.stderr}", err=True)
            return None


# Work order template with inline comments (JSON "//" convention)
_WORK_ORDER_TEMPLATE = {
    "// repo_url": "REQUIRED. Git repository URL (used as project identifier).",
    "repo_url": "https://github.com/user/project",
    "// version": "REQUIRED. Git tag, branch, or commit hash to analyze.",
    "version": "v1.0",
    "// path": "Local path to project source. If missing or invalid, auto-clones from repo_url.",
    "path": "./project-src",
    "// build_script": "Custom build script (relative to project root). null = auto-detect.",
    "build_script": None,
    "// backend": "Analysis backend: 'auto' (default), 'svf', 'joern', 'introspector', 'prebuild'.",
    "backend": "auto",
    "// language": "Override language detection. null = auto-detect from source files.",
    "language": None,
    "// fuzzer_sources": "REQUIRED. Map of fuzzer_name -> list of source files.",
    "fuzzer_sources": {
        "fuzz_example": ["fuzz/fuzz_example.c"],
    },
    "// fuzz_tooling_url": "Git URL for external fuzzer harness repo. null = harness in project.",
    "fuzz_tooling_url": None,
    "// fuzz_tooling_ref": "Branch/tag/commit for fuzz_tooling_url. null = default branch.",
    "fuzz_tooling_ref": None,
    "// diff_files": "List of changed files for incremental analysis. null = full analysis.",
    "diff_files": None,
    "// ai_refine": "Enable AI-assisted refinement (v2 feature, not implemented in v1).",
    "ai_refine": False,
}


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def main(verbose: bool) -> None:
    """Z-Code-Analyzer: Static analysis engine for call graph extraction."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    # Suppress noisy neo4j driver notifications (index already exists, etc.)
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


@main.command("create-work")
@click.option("-o", "--output", default="work.json", help="Output file path")
def create_work(output: str) -> None:
    """Generate a work order template JSON file."""
    raw = json.dumps(_WORK_ORDER_TEMPLATE, indent=2)
    # Insert blank lines between field groups (before each "// " comment key)
    lines = raw.split("\n")
    out_lines: list[str] = []
    for line in lines:
        if '"// ' in line and out_lines and out_lines[-1].strip() not in ("{", ""):
            out_lines.append("")
        out_lines.append(line)
    Path(output).write_text("\n".join(out_lines) + "\n")
    click.echo(f"Work order template written to {output}")
    click.echo()
    click.echo("Next steps:")
    click.echo("  1. Edit the file — fill in repo_url, version, and fuzzer_sources")
    click.echo("  2. Remove the '// ...' comment keys if you want clean JSON")
    click.echo(f"  3. Run:  z-analyze run {output}")


@main.command("run")
@click.argument("work_file", type=click.Path(exists=True))
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth ('none' or 'user:password')")
@click.option("--pg-url", default=_DEFAULT_PG_URL, help="PostgreSQL URL")
def run(
    work_file: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
) -> None:
    """Execute analysis from a work order JSON file."""
    # Load and validate work order
    try:
        work = json.loads(Path(work_file).read_text())
    except json.JSONDecodeError as e:
        click.echo(f"Error: Invalid JSON in {work_file}: {e}", err=True)
        sys.exit(1)

    # Validate required fields
    for field in ("repo_url", "version", "fuzzer_sources"):
        if field not in work:
            click.echo(f"Error: Missing required field '{field}' in work order", err=True)
            sys.exit(1)

    if not isinstance(work["fuzzer_sources"], dict):
        click.echo("Error: 'fuzzer_sources' must be a JSON object", err=True)
        sys.exit(1)

    project_path = work.get("path")
    if not project_path or not Path(project_path).is_dir():
        # Auto-clone if path not provided (doc §9.1: "不传则自动 clone")
        repo_url = work["repo_url"]
        version = work.get("version", "HEAD")
        click.echo(f"Local path not found, cloning {repo_url}@{version} ...")
        project_path = _auto_clone(repo_url, version)
        if not project_path:
            click.echo("Error: auto-clone failed.", err=True)
            sys.exit(1)
        click.echo(f"Cloned to: {project_path}")

    # Run analysis
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.models.snapshot import ZCABase
    from z_code_analyzer.orchestrator import StaticAnalysisOrchestrator
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)

    graph_store = GraphStore(neo4j_uri, auth)

    engine = create_engine(pg_url)
    ZCABase.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)

    snapshot_mgr = SnapshotManager(session_factory=session_factory, graph_store=graph_store)

    orchestrator = StaticAnalysisOrchestrator(
        snapshot_manager=snapshot_mgr,
        graph_store=graph_store,
    )

    cloned_dir = None  # Track if we auto-cloned, for cleanup
    if project_path != work.get("path"):
        cloned_dir = project_path

    try:
        try:
            result = asyncio.run(
                orchestrator.analyze(
                    project_path=project_path,
                    repo_url=work["repo_url"],
                    version=work["version"],
                    fuzzer_sources=work["fuzzer_sources"],
                    build_script=work.get("build_script"),
                    language=work.get("language"),
                    backend=work.get("backend"),
                    diff_files=work.get("diff_files"),
                    svf_case_config=work.get("svf_case_config"),
                    svf_docker_image=work.get("svf_docker_image"),
                    fuzz_tooling_url=work.get("fuzz_tooling_url"),
                    fuzz_tooling_ref=work.get("fuzz_tooling_ref"),
                )
            )
        except Exception as exc:
            click.echo(f"Error: {exc}", err=True)
            raise SystemExit(1) from exc

        click.echo(f"\nAnalysis {'(cached)' if result.cached else 'complete'}:")
        click.echo(f"  Snapshot ID: {result.snapshot_id}")
        click.echo(f"  Backend: {result.backend}")
        click.echo(f"  Functions: {result.function_count}")
        click.echo(f"  Edges: {result.edge_count}")
        click.echo(f"  Fuzzers: {result.fuzzer_names}")

        # Print progress summary
        summary = orchestrator.progress.get_summary()
        click.echo(f"\nPipeline summary (total: {summary['total_duration']}s):")
        for p in summary["phases"]:
            status_icon = {
                "completed": "+",
                "failed": "!",
                "skipped": "-",
                "running": "~",
                "pending": ".",
            }.get(p["status"], "?")
            duration = f" ({p['duration']}s)" if p["duration"] else ""
            detail = f" - {p['detail']}" if p["detail"] else ""
            click.echo(f"  [{status_icon}] {p['phase']}{duration}{detail}")

    finally:
        graph_store.close()
        snapshot_mgr.close()
        # Clean up auto-cloned repo
        if cloned_dir:
            import shutil

            shutil.rmtree(cloned_dir, ignore_errors=True)


@main.command("probe")
@click.argument("project_path", type=click.Path(exists=True))
def probe(project_path: str) -> None:
    """Quick project probe: detect language, build system, source files."""
    from z_code_analyzer.probe import ProjectProbe

    info = ProjectProbe().probe(project_path)
    click.echo(
        f"Language: {info.language_profile.primary_language} "
        f"(confidence: {info.language_profile.confidence})"
    )
    click.echo(f"Build system: {info.build_system}")
    click.echo(f"Source files: {len(info.source_files)}")
    click.echo(f"Estimated LOC: {info.estimated_loc}")
    if info.git_root:
        click.echo(f"Git root: {info.git_root}")
    click.echo("\nFile counts:")
    for ext, count in sorted(info.language_profile.file_counts.items()):
        click.echo(f"  {ext}: {count}")


# ── z-query CLI ──


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def query_main(verbose: bool) -> None:
    """Z-Code Query: Query analysis results in Neo4j."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


@query_main.command("shortest-path")
@click.option("--repo-url", required=True, help="Repository URL")
@click.option("--version", required=True, help="Version/tag/commit")
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth ('none' or 'user:password')")
@click.option("--pg-url", default=_DEFAULT_PG_URL, help="PostgreSQL URL")
@click.argument("from_func")
@click.argument("to_func")
def query_shortest_path(
    repo_url: str,
    version: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
    from_func: str,
    to_func: str,
) -> None:
    """Find shortest path between two functions."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    engine = create_engine(pg_url)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine))

    try:
        snap = sm.find_snapshot(repo_url, version)
        if not snap:
            click.echo(f"No snapshot found for {repo_url}@{version}", err=True)
            sys.exit(1)
        sid = str(snap.id)
        result = gs.shortest_path(sid, from_func, to_func)
        if result:
            click.echo(json.dumps(result, indent=2, default=str))
        else:
            click.echo(f"No path from {from_func} to {to_func}")
    finally:
        gs.close()
        sm.close()


@query_main.command("search")
@click.option("--repo-url", required=True, help="Repository URL")
@click.option("--version", required=True, help="Version/tag/commit")
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth")
@click.option("--pg-url", default=_DEFAULT_PG_URL, help="PostgreSQL URL")
@click.argument("pattern")
def query_search(
    repo_url: str,
    version: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
    pattern: str,
) -> None:
    """Search functions by pattern (e.g. 'parse_*')."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    engine = create_engine(pg_url)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine))

    try:
        snap = sm.find_snapshot(repo_url, version)
        if not snap:
            click.echo(f"No snapshot found for {repo_url}@{version}", err=True)
            sys.exit(1)
        results = gs.search_functions(str(snap.id), pattern)
        for func in results:
            click.echo(
                f"  {func['name']}  {func.get('file_path', '')}:{func.get('start_line', '')}"
            )
    finally:
        gs.close()
        sm.close()


# ── z-snapshots CLI ──


@click.group()
@click.option("-v", "--verbose", is_flag=True, help="Verbose logging")
def snapshots_main(verbose: bool) -> None:
    """Z-Code Snapshots: Manage analysis snapshots."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    logging.getLogger("neo4j.notifications").setLevel(logging.WARNING)


@snapshots_main.command("list")
@click.option("--repo-url", default=None, help="Filter by repository URL")
@click.option("--pg-url", default=_DEFAULT_PG_URL, help="PostgreSQL URL")
def snapshots_list(repo_url: str | None, pg_url: str) -> None:
    """List all analysis snapshots."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.snapshot_manager import SnapshotManager

    engine = create_engine(pg_url)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine))
    try:
        snaps = sm.list_snapshots(repo_url=repo_url)
        if not snaps:
            click.echo("No snapshots found.")
            return
        for snap in snaps:
            click.echo(
                f"  {str(snap.id)[:12]}  "
                f"{(snap.repo_name or '?'):20s}  "
                f"{(snap.version or '?'):15s}  "
                f"{(snap.backend or '?'):10s}  "
                f"funcs={snap.node_count:5d}  "
                f"edges={snap.edge_count:5d}  "
                f"fuzzers={len(snap.fuzzer_names or [])}"
            )
    finally:
        sm.close()


def _resolve_auth(neo4j_auth: str | None) -> tuple[str, str] | None:
    """Resolve Neo4j auth from CLI flag or env."""
    if neo4j_auth is not None:
        if neo4j_auth.lower() == "none":
            return None
        if ":" in neo4j_auth:
            user, password = neo4j_auth.split(":", 1)
            return (user, password)
        logging.getLogger(__name__).warning(
            "--neo4j-auth has unrecognized format (expected 'none' or 'user:password'), "
            "treating as no-auth"
        )
        return None
    return _parse_neo4j_auth()


# ── z-analyze auto ──


@main.command("auto")
@click.argument("target", required=False, default=None)
@click.option("--project", default=None, help="OSS-Fuzz project name (e.g., libpng)")
@click.option("--repo-url", default=None, help="GitHub repo URL")
@click.option("--version", default="HEAD", help="Version/tag/commit to analyze")
@click.option("--branch", default="", help="Git branch")
@click.option("--language", default="", help="Override language detection")
@click.option("--fuzzer", "fuzzer_names", multiple=True, help="Fuzzer binary name(s)")
@click.option("--fuzzer-source", "fuzzer_source_paths", multiple=True,
              help="Path(s) to fuzzer source files (.c/.cc/.cpp)")
@click.option(
    "--ossfuzz-repo",
    default=None,
    help="Path to oss-fuzz repo (auto-detect if not set)",
)
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth")
@click.option(
    "--pg-url",
    default=_DEFAULT_PG_URL,
    help="PostgreSQL URL",
)
@click.option("--docker-image", default="", help="Explicit Docker image")
@click.option("--backend", default="", help="Analysis backend: 'svf', 'joern', or '' (auto-select)")
@click.option("--force", is_flag=True, help="Force re-analysis even if snapshot exists")
def auto_analyze(
    target: str | None,
    project: str | None,
    repo_url: str | None,
    version: str,
    branch: str,
    language: str,
    fuzzer_names: tuple[str, ...],
    fuzzer_source_paths: tuple[str, ...],
    ossfuzz_repo: str | None,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
    docker_image: str,
    backend: str,
    force: bool,
) -> None:
    """Fully automated analysis of a repo or oss-fuzz project.

    \b
    Examples:
      # Pure call graph (no fuzzer):
      z-analyze auto --repo-url https://github.com/antirez/sds

      # With fuzzer source file:
      z-analyze auto --repo-url https://github.com/madler/zlib \\
          --fuzzer-source /path/to/my_fuzzer.c

      # OSS-Fuzz project:
      z-analyze auto libpng --ossfuzz-repo /path/to/oss-fuzz

      # Force Joern backend:
      z-analyze auto --repo-url https://github.com/nlohmann/json --backend joern
    """
    # Resolve target from positional arg, --project, or --repo-url
    if target is None and project is None and repo_url is None:
        click.echo("Error: provide a TARGET argument, --project, or --repo-url", err=True)
        raise SystemExit(1)
    if target is None:
        target = repo_url if repo_url else project

    # Auto-detect oss-fuzz repo
    if ossfuzz_repo is None:
        for candidate in ["/home/ze/oss-fuzz", os.path.expanduser("~/oss-fuzz"), "/tmp/oss-fuzz"]:
            if os.path.isdir(os.path.join(candidate, "projects")):
                ossfuzz_repo = candidate
                break
        if ossfuzz_repo is None:
            ossfuzz_repo = ""

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.auto_pipeline import AutoAnalysisRequest, AutoPipeline
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.models.snapshot import ZCABase
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    engine = create_engine(pg_url)
    ZCABase.metadata.create_all(engine)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine), graph_store=gs)

    pipeline = AutoPipeline(
        snapshot_manager=sm,
        graph_store=gs,
        ossfuzz_repo_path=ossfuzz_repo,
        neo4j_uri=neo4j_uri,
    )

    # Determine if target is a URL or oss-fuzz project name
    is_url = target.startswith("http://") or target.startswith("https://")

    # For non-URL targets without oss-fuzz, default to joern
    resolved_backend = backend
    if not resolved_backend and not is_url:
        # Check if it's an OSS-Fuzz project
        if ossfuzz_repo and os.path.isdir(os.path.join(ossfuzz_repo, "projects", target)):
            pass  # let auto-select decide
        else:
            resolved_backend = "joern"  # non-OSS-Fuzz, default to joern

    request = AutoAnalysisRequest(
        repo_url=target if is_url else "",
        ossfuzz_project="" if is_url else target,
        version=version,
        branch=branch,
        language=language,
        fuzzer_names=list(fuzzer_names),
        fuzzer_source_paths=list(fuzzer_source_paths),
        backend=resolved_backend,
        ossfuzz_repo_path=ossfuzz_repo,
        docker_image=docker_image,
        force=force,
    )

    try:
        result = pipeline.run(request)
        click.echo(result.summary())

        # Show fuzzer details if any
        if result.fuzzer_names:
            click.echo(f"\nFuzzer reachability:")
            for fn in result.fuzzer_names:
                click.echo(f"  {fn}")

        if not result.success:
            raise SystemExit(1)
    finally:
        gs.close()
        sm.close()


@main.command("source")
@click.argument("target", required=False, default=None)
@click.option("--repo-url", default=None, help="Git repo URL to analyze")
@click.option("--path", "project_path", default=None, help="Local source directory")
@click.option("--project", default=None, help="Project name (auto-detected if omitted)")
@click.option("--version", default="HEAD", help="Tag, branch, commit hash, or PR (e.g. v1.6.44, abc1234, PR:42)")
@click.option("--branch", default="", help="Git branch (alias for --version)")
@click.option("--language", default="", help="Override language detection")
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth")
@click.option(
    "--pg-url",
    default=_DEFAULT_PG_URL,
    help="PostgreSQL URL",
)
@click.option("--force", is_flag=True, help="Force re-analysis even if snapshot exists")
def source_analyze(
    target: str | None,
    repo_url: str | None,
    project_path: str | None,
    project: str | None,
    version: str,
    branch: str,
    language: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
    force: bool,
) -> None:
    """Full source-code analysis (compiles ALL source files, not just fuzzer targets).

    Accepts a git URL, local path, or both:

    \b
      z-analyze source https://github.com/pnggroup/libpng
      z-analyze source --path /path/to/libpng
      z-analyze source --repo-url https://github.com/pnggroup/libpng
    """
    # Resolve target
    if target is None and repo_url is None and project_path is None:
        click.echo("Error: provide a TARGET URL, --repo-url, or --path", err=True)
        raise SystemExit(1)

    if target is not None:
        if target.startswith("http://") or target.startswith("https://") or target.startswith("git://"):
            repo_url = repo_url or target
        elif Path(target).is_dir():
            project_path = project_path or target
        else:
            # Assume it's a URL
            repo_url = repo_url or target

    if not repo_url and not project_path:
        click.echo("Error: need --repo-url or --path to a local source directory", err=True)
        raise SystemExit(1)

    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.models.snapshot import ZCABase
    from z_code_analyzer.snapshot_manager import SnapshotManager
    from z_code_analyzer.source_pipeline import SourceAnalysisRequest, SourcePipeline

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    engine = create_engine(pg_url)
    ZCABase.metadata.create_all(engine)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine), graph_store=gs)

    pipeline = SourcePipeline(
        snapshot_manager=sm,
        graph_store=gs,
        neo4j_uri=neo4j_uri,
    )

    request = SourceAnalysisRequest(
        repo_url=repo_url or "",
        project_path=project_path or "",
        project_name=project or "",
        version=version,
        branch=branch,
        language=language,
        force=force,
    )

    try:
        result = pipeline.run(request)
        click.echo(result.summary())
        if not result.success:
            raise SystemExit(1)
    finally:
        gs.close()
        sm.close()


@main.command("batch")
@click.option("--limit", default=100, help="Max number of projects")
@click.option("--parallel", default=1, help="Max concurrent builds")
@click.option("--retry", default=1, help="Retry count per project")
@click.option(
    "--ossfuzz-repo",
    default=None,
    help="Path to oss-fuzz repo",
)
@click.option("--neo4j-uri", default=_DEFAULT_NEO4J_URI, help="Neo4j URI")
@click.option("--neo4j-auth", default=None, help="Neo4j auth")
@click.option(
    "--pg-url",
    default=_DEFAULT_PG_URL,
    help="PostgreSQL URL",
)
@click.option(
    "--results-file",
    default="batch_results.json",
    help="Path for JSON results file",
)
@click.option("--pull/--no-pull", default=True, help="Pull missing Docker images")
@click.option("--projects", default="", help="Comma-separated project names")
def batch_analyze(
    limit: int,
    parallel: int,
    retry: int,
    ossfuzz_repo: str,
    neo4j_uri: str,
    neo4j_auth: str | None,
    pg_url: str,
    results_file: str,
    pull: bool,
    projects: str,
) -> None:
    """Batch analyze oss-fuzz C/C++ projects."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.models.snapshot import ZCABase
    from z_code_analyzer.ossfuzz.batch_runner import BatchRunner
    from z_code_analyzer.snapshot_manager import SnapshotManager

    auth = _resolve_auth(neo4j_auth)
    gs = GraphStore(neo4j_uri, auth)
    engine = create_engine(pg_url)
    ZCABase.metadata.create_all(engine)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine), graph_store=gs)

    runner = BatchRunner(
        snapshot_manager=sm,
        graph_store=gs,
        ossfuzz_repo_path=ossfuzz_repo,
        neo4j_uri=neo4j_uri,
    )

    project_names = [p.strip() for p in projects.split(",") if p.strip()] or None

    try:
        result = runner.run(
            limit=limit,
            max_parallel=parallel,
            retry_count=retry,
            project_names=project_names,
            pull_images=pull,
            results_file=results_file,
        )
        click.echo(result.summary())
        if result.failed > 0:
            click.echo(
                f"\n{result.failed} projects failed. "
                f"See {results_file} for details.",
                err=True,
            )
    finally:
        gs.close()
        sm.close()


@main.command("ossfuzz-list")
@click.option(
    "--ossfuzz-repo",
    default=None,
    help="Path to oss-fuzz repo",
)
@click.option("--limit", default=200, help="Max number of projects to list")
def ossfuzz_list(ossfuzz_repo: str, limit: int) -> None:
    """List available C/C++ projects from oss-fuzz."""
    from z_code_analyzer.ossfuzz.crawler import OSSFuzzCrawler

    crawler = OSSFuzzCrawler(ossfuzz_repo)
    projects = crawler.crawl(limit=limit, require_docker_image=False)
    click.echo(f"{'Name':25s} {'Lang':5s} {'Docker':8s} {'Fuzzers':8s} {'Repo'}")
    click.echo("-" * 100)
    for p in projects:
        fcount = len(p.fuzzer_targets)
        img_status = "YES" if p.docker_image_available else "no"
        click.echo(
            f"{p.name:25s} {p.language:5s} {img_status:8s} {fcount:8d} {p.main_repo}"
        )
    click.echo(f"\nTotal: {len(projects)} C/C++ projects")


if __name__ == "__main__":
    main()

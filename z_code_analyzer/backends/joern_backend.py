"""Joern analysis backend — source-level call graph extraction for C/C++.

No compilation required. Uses joern-parse + joern script queries.
Best for C++ projects where wllvm/SVF fails (CMake, templates, namespaces).
"""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from z_code_analyzer.backends.base import (
    AnalysisBackend,
    AnalysisResult,
    CallEdge,
    CallType,
    FunctionRecord,
)

logger = logging.getLogger(__name__)

JOERN_PARSE_TIMEOUT = 1800  # 30 min for parsing
JOERN_QUERY_TIMEOUT = 600   # 10 min for queries


class JoernBackend(AnalysisBackend):
    """
    Joern-based static analysis backend for C/C++.

    Workflow:
        source_dir -> joern-parse -> CPG -> joern script queries
            -> {functions, edges} -> AnalysisResult

    Strengths:
        - No compilation needed (parses source text directly)
        - Works with CMake/C++ projects where wllvm fails
        - Fast for medium-sized projects

    Limitations:
        - No pointer analysis (function pointers not resolved)
        - C++ namespace/template resolution can be incomplete
        - Cannot track into external libraries
    """

    @property
    def name(self) -> str:
        return "joern"

    @property
    def supported_languages(self) -> set[str]:
        return {"c", "cpp"}

    def get_descriptor(self):
        from z_code_analyzer.backends.registry import (
            BackendCapability,
            BackendDescriptor,
        )
        return BackendDescriptor(
            name="joern",
            supported_languages={"c", "cpp"},
            capabilities={
                BackendCapability.FUNCTION_EXTRACTION,
                BackendCapability.DIRECT_CALLS,
                BackendCapability.COMPLEXITY_METRICS,
            },
            precision_score=0.75,  # Lower than SVF (no pointer analysis)
            speed_score=0.90,      # Faster (no compilation needed)
            prerequisites=["joern-parse", "joern"],
            factory=JoernBackend,
        )

    def analyze(
        self,
        project_path: str,
        language: str,
        **kwargs: Any,
    ) -> AnalysisResult:
        """
        Run Joern analysis on source code.

        Optional kwargs:
            cpg_path: str — path to pre-built CPG (skip joern-parse)
            max_call_depth: int — max transitive call depth for reachability (default 10)
        """
        start = time.monotonic()
        project_path = str(Path(project_path).resolve())

        cpg_path = kwargs.get("cpg_path")
        if not cpg_path:
            cpg_path = self._parse_project(project_path)

        functions, edges = self._query_callgraph(cpg_path, project_path)

        duration = time.monotonic() - start

        return AnalysisResult(
            functions=functions,
            edges=edges,
            language=language,
            backend="joern",
            analysis_duration_seconds=round(duration, 2),
            metadata={
                "cpg_path": cpg_path,
                "node_count": len(functions),
                "edge_count": len(edges),
            },
        )

    def _parse_project(self, project_path: str) -> str:
        """Run joern-parse to generate CPG."""
        cpg_path = tempfile.mktemp(suffix=".cpg", prefix="joern-")

        logger.info("Running joern-parse on %s -> %s", project_path, cpg_path)
        try:
            result = subprocess.run(
                ["joern-parse", project_path, "-o", cpg_path],
                capture_output=True,
                text=True,
                timeout=JOERN_PARSE_TIMEOUT,
            )
            if result.returncode != 0:
                logger.warning("joern-parse stderr: %s", result.stderr[-2000:])
            if not Path(cpg_path).exists():
                raise RuntimeError(
                    f"joern-parse did not produce CPG. stderr: {result.stderr[-1000:]}"
                )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"joern-parse timed out after {JOERN_PARSE_TIMEOUT}s")

        logger.info("CPG created: %s", cpg_path)
        return cpg_path

    def _query_callgraph(
        self, cpg_path: str, project_path: str
    ) -> tuple[list[FunctionRecord], list[CallEdge]]:
        """Query CPG for functions and call edges using joern script."""

        # Write a Joern script that outputs JSON
        script = self._build_query_script(cpg_path)

        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".sc", prefix="joern-query-", delete=False
        ) as f:
            f.write(script)
            script_path = f.name

        logger.info("Running joern query script: %s", script_path)
        try:
            result = subprocess.run(
                ["joern", "--script", script_path],
                capture_output=True,
                text=True,
                timeout=JOERN_QUERY_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"joern query timed out after {JOERN_QUERY_TIMEOUT}s")
        finally:
            Path(script_path).unlink(missing_ok=True)

        # Parse JSON output from the script
        return self._parse_script_output(result.stdout, project_path)

    def _build_query_script(self, cpg_path: str) -> str:
        """Build a Joern Scala script that extracts functions and call edges as JSON."""
        return f'''
importCpg("{cpg_path}")

import scala.collection.mutable.ArrayBuffer

// Collect internal functions
val funcData = ArrayBuffer[String]()
cpg.method.internal.l.foreach {{ m =>
  val name = m.name
  val file = m.file.name.headOption.getOrElse("")
  val line = m.lineNumber.getOrElse(0)
  val endLine = m.lineNumberEnd.getOrElse(0)
  // Escape for JSON
  val escapedName = name.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
  val escapedFile = file.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
  funcData += s"""{{"name":"$escapedName","file":"$escapedFile","line":$line,"end_line":$endLine}}"""
}}

// Collect call edges (caller -> callee name)
val edgeData = ArrayBuffer[String]()
cpg.call.l.foreach {{ c =>
  val callerName = c.method.name
  val calleeName = c.name
  val calleeFullName = c.methodFullName
  val line = c.lineNumber.getOrElse(0)
  val file = c.file.name.headOption.getOrElse("")
  // Skip operators
  if (!calleeName.startsWith("<operator>") && !calleeName.startsWith("<operators>")) {{
    val escapedCaller = callerName.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
    val escapedCallee = calleeName.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
    val escapedFull = calleeFullName.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
    val escapedFile = file.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
    edgeData += s"""{{"caller":"$escapedCaller","callee":"$escapedCallee","callee_full":"$escapedFull","file":"$escapedFile","line":$line}}"""
  }}
}}

// Output as JSON
println("JOERN_FUNCTIONS_START")
println("[" + funcData.mkString(",\\n") + "]")
println("JOERN_FUNCTIONS_END")
println("JOERN_EDGES_START")
println("[" + edgeData.mkString(",\\n") + "]")
println("JOERN_EDGES_END")
'''

    def _parse_script_output(
        self, stdout: str, project_path: str
    ) -> tuple[list[FunctionRecord], list[CallEdge]]:
        """Parse JSON output from Joern script."""
        functions: list[FunctionRecord] = []
        edges: list[CallEdge] = []

        # Extract functions JSON
        func_json = self._extract_section(stdout, "JOERN_FUNCTIONS_START", "JOERN_FUNCTIONS_END")
        if func_json:
            try:
                func_list = json.loads(func_json)
                for f in func_list:
                    name = f.get("name", "")
                    if name in ("<global>", "<clinit>"):
                        continue
                    functions.append(
                        FunctionRecord(
                            name=name,
                            file_path=f.get("file", ""),
                            start_line=f.get("line", 0),
                            end_line=f.get("end_line", 0),
                            content="",  # Not extracted for performance
                            language="cpp",
                            source_backend="joern",
                        )
                    )
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse functions JSON: %s", e)

        # Extract edges JSON
        edge_json = self._extract_section(stdout, "JOERN_EDGES_START", "JOERN_EDGES_END")
        if edge_json:
            try:
                edge_list = json.loads(edge_json)
                for e in edge_list:
                    caller = e.get("caller", "")
                    callee = e.get("callee", "")
                    if caller and callee and caller != "<global>" and callee != "<global>":
                        edges.append(
                            CallEdge(
                                caller=caller,
                                callee=callee,
                                call_type=CallType.DIRECT,
                                call_site_file=e.get("file", ""),
                                call_site_line=e.get("line", 0),
                                source_backend="joern",
                            )
                        )
            except json.JSONDecodeError as e:
                logger.warning("Failed to parse edges JSON: %s", e)

        # Deduplicate edges (same caller->callee pair)
        seen = set()
        unique_edges = []
        for edge in edges:
            key = (edge.caller, edge.callee)
            if key not in seen:
                seen.add(key)
                unique_edges.append(edge)

        logger.info(
            "Joern extracted %d functions, %d unique edges (from %d call sites)",
            len(functions), len(unique_edges), len(edges),
        )

        return functions, unique_edges

    @staticmethod
    def _extract_section(text: str, start_marker: str, end_marker: str) -> str | None:
        """Extract text between markers."""
        start_idx = text.find(start_marker)
        end_idx = text.find(end_marker)
        if start_idx == -1 or end_idx == -1:
            return None
        return text[start_idx + len(start_marker):end_idx].strip()

    def check_prerequisites(self, project_path: str) -> list[str]:
        missing = []
        for tool in ["joern-parse", "joern"]:
            try:
                result = subprocess.run(
                    ["which", tool],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode != 0:
                    missing.append(f"{tool} not found in PATH")
            except (subprocess.SubprocessError, FileNotFoundError):
                missing.append(f"{tool} not available")
        return missing

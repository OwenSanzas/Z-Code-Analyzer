#!/usr/bin/env python3
"""Fix all NOT-OK projects using Joern backend.

For each project:
1. Clone source from OSS-Fuzz Dockerfile's git clone URL
2. Copy fuzzer sources into the project
3. Run Joern backend (joern-parse + query)
4. Compute reachability for each benchmark case
5. Update results
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from z_code_analyzer.backends.joern_backend import JoernBackend

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

OSSFUZZ_DIR = "/home/ze/oss-fuzz"
WORK_DIR = Path("/home/ze/Z-Code-Analyzer/joern-workspace")
RESULTS_FILE = Path("/home/ze/Z-Code-Analyzer/results/batch_results.json")

# Projects that need fixing (NOT OK from manual review)
FIX_PROJECTS = [
    # LOW funcs (wllvm failed)
    "curl", "draco", "easywsclient", "flatbuffers", "flex", "glslang",
    "icu", "openexr", "pugixml", "simdjson", "wabt", "yajl-ruby",
    # FAIL
    "binutils", "gdal", "haproxy",
    # reach=0 with good SVF data
    "bad_example", "boost", "clamav", "libical", "libjxl", "libplist",
    "libxslt", "llamacpp", "nettle", "opencv", "openssh", "openssl", "zlib",
    # Arrow already fixed separately
]


def get_repo_url(project: str) -> str:
    """Extract git clone URL from OSS-Fuzz Dockerfile."""
    dockerfile = Path(OSSFUZZ_DIR) / "projects" / project / "Dockerfile"
    if not dockerfile.exists():
        return ""
    content = dockerfile.read_text()
    # Match: git clone [options] <url> [dest]
    for line in content.splitlines():
        m = re.search(r'git clone\s+(?:--[^\s]+\s+)*(?:--recurse-submodules\s+)?(\S+)', line)
        if m:
            url = m.group(1)
            if url.startswith("http") or url.startswith("git"):
                return url
    return ""


def get_fuzzer_sources(project: str) -> list[str]:
    """Find fuzzer source files from OSS-Fuzz project dir."""
    project_dir = Path(OSSFUZZ_DIR) / "projects" / project
    sources = []
    for ext in ["*.c", "*.cc", "*.cpp", "*.cxx"]:
        for f in project_dir.glob(ext):
            if f.read_text(errors="replace").find("LLVMFuzzerTestOneInput") >= 0:
                sources.append(str(f))
    return sources


def clone_project(project: str, repo_url: str) -> str | None:
    """Clone project source."""
    dest = WORK_DIR / project
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth=1", repo_url, str(dest)],
            capture_output=True, text=True, timeout=300,
        )
        if dest.exists():
            return str(dest)
    except Exception as e:
        logger.warning("Clone failed for %s: %s", project, e)
    return None


def compute_reachability_joern(cpg_path: str, benchmark_fuzzers: list[str]) -> dict:
    """Use Joern to compute reachability for each benchmark fuzzer.

    Strategy: manually resolve function names through call chain,
    handling C++ namespace issues.
    """
    # Build a query that finds LLVMFuzzerTestOneInput entry points and traces calls
    script = f'''
importCpg("{cpg_path}")

import scala.collection.mutable

def resolveCallees(startName: String, maxDepth: Int): Set[String] = {{
  val visited = mutable.Set[String]()
  var frontier = Set(startName)

  for (depth <- 1 to maxDepth) {{
    val nextFrontier = mutable.Set[String]()
    for (fn <- frontier if !visited.contains(fn)) {{
      visited += fn
      cpg.method.name(fn).l.foreach {{ m =>
        m.call.l.foreach {{ c =>
          val full = c.methodFullName
          if (!full.startsWith("<operator>") && !full.startsWith("<operators>")) {{
            val name = if (full.contains(".")) {{
              val beforeColon = if (full.contains(":")) full.split(":")(0) else full
              beforeColon.split("\\\\.").last
            }} else if (full.contains("::")) {{
              full.split("::").last.split("\\\\(")(0)
            }} else {{
              full.split(":")(0)
            }}
            if (name.nonEmpty && name != "<global>") nextFrontier += name
          }}
        }}
      }}
    }}
    frontier = (nextFrontier -- visited).toSet
  }}
  visited.toSet - startName
}}

// Find all LLVMFuzzerTestOneInput methods and their files
val fuzzEntries = cpg.method.name("LLVMFuzzerTestOneInput").l.map {{ m =>
  val file = m.file.name.headOption.getOrElse("")
  val directCalls = m.call.filterNot(_.methodFullName.startsWith("<operator>"))
    .filterNot(_.methodFullName.startsWith("<operators>"))
    .map(c => {{
      val full = c.methodFullName
      val name = if (full.contains(".")) {{
        val beforeColon = if (full.contains(":")) full.split(":")(0) else full
        beforeColon.split("\\\\.").last
      }} else if (full.contains("::")) {{
        full.split("::").last.split("\\\\(")(0)
      }} else {{
        full.split(":")(0)
      }}
      name
    }}).toSet.filterNot(_.isEmpty).filterNot(_ == "<global>")
  (file, directCalls)
}}

println("JOERN_REACH_START")
fuzzEntries.foreach {{ case (file, directCalls) =>
  // Trace transitive from each direct call
  var allReachable = Set[String]()
  for (fn <- directCalls) {{
    allReachable ++= resolveCallees(fn, 5)
  }}
  allReachable ++= directCalls
  // Filter to internal only
  val internal = allReachable.filter(name => cpg.method.internal.name(name).size > 0)
  val escapedFile = file.replace("\\\\", "\\\\\\\\").replace("\\"", "\\\\\\"")
  println(s"""FUZZ:$escapedFile:${{internal.size}}:${{internal.toList.sorted.mkString(",")}}""")
}}
println("JOERN_REACH_END")
'''

    with open("/tmp/joern_reach.sc", "w") as f:
        f.write(script)

    try:
        result = subprocess.run(
            ["joern", "--script", "/tmp/joern_reach.sc"],
            capture_output=True, text=True, timeout=600,
        )
        stdout = result.stdout
    except subprocess.TimeoutExpired:
        logger.warning("Joern query timed out")
        return {}

    # Parse output
    reach_data = {}
    in_section = False
    for line in stdout.splitlines():
        if "JOERN_REACH_START" in line:
            in_section = True
            continue
        if "JOERN_REACH_END" in line:
            break
        if in_section and line.startswith("FUZZ:"):
            parts = line.split(":", 3)
            if len(parts) >= 3:
                fuzz_file = parts[1]
                count = int(parts[2]) if parts[2].isdigit() else 0
                funcs = parts[3].split(",") if len(parts) > 3 and parts[3] else []
                # Extract fuzzer name from file path
                fname = Path(fuzz_file).stem
                reach_data[fname] = {"count": count, "functions": funcs}

    # Match benchmark fuzzers to detected fuzzers
    result_reach = {}
    for bfz in benchmark_fuzzers:
        best_match = 0
        for fname, data in reach_data.items():
            if bfz in fname or fname in bfz or bfz.replace("-", "_") in fname or fname.replace("-", "_") in bfz:
                best_match = max(best_match, data["count"])
        result_reach[bfz] = best_match

    return result_reach


def process_project(project: str, benchmark_fuzzers: list[str]) -> dict:
    """Process a single project with Joern."""
    t0 = time.monotonic()
    result = {
        "project": project,
        "joern_success": False,
        "joern_functions": 0,
        "joern_edges": 0,
        "joern_duration_sec": 0,
        "joern_reachability": {},
    }

    # 1. Use already-cloned source if available, otherwise clone
    existing_dir = WORK_DIR / project
    if existing_dir.exists() and any(existing_dir.iterdir()):
        project_dir = str(existing_dir)
        logger.info("[%s] Using existing source at %s", project, project_dir)
    else:
        repo_url = get_repo_url(project)
        if not repo_url:
            logger.warning("[%s] No repo URL found in Dockerfile", project)
            result["joern_error"] = "no repo URL"
            return result
        project_dir = clone_project(project, repo_url)
        if not project_dir:
            logger.warning("[%s] Clone failed", project)
            result["joern_error"] = "clone failed"
            return result

    # 2. Copy fuzzer sources into project dir (if not already there)
    fuzzer_sources = get_fuzzer_sources(project)
    for src in fuzzer_sources:
        dest_file = Path(project_dir) / Path(src).name
        if not dest_file.exists():
            shutil.copy2(src, project_dir)

    # 3. Run Joern backend
    try:
        backend = JoernBackend()
        analysis = backend.analyze(project_dir, "cpp")
        result["joern_functions"] = len(analysis.functions)
        result["joern_edges"] = len(analysis.edges)
        result["joern_success"] = True
        cpg_path = analysis.metadata.get("cpg_path", "")
    except Exception as e:
        logger.warning("[%s] Joern analysis failed: %s", project, e)
        result["joern_error"] = str(e)[:200]
        result["joern_duration_sec"] = time.monotonic() - t0
        return result

    # 4. Compute reachability
    if cpg_path:
        reach = compute_reachability_joern(cpg_path, benchmark_fuzzers)
        result["joern_reachability"] = reach

    result["joern_duration_sec"] = round(time.monotonic() - t0, 1)
    return result


def main():
    WORK_DIR.mkdir(parents=True, exist_ok=True)

    # Load existing results
    d = json.load(open(RESULTS_FILE))

    # Get benchmark fuzzers for each project
    project_fuzzers = {}
    for r in d:
        project_fuzzers[r["project"]] = r.get("benchmark_fuzzers", [])

    total = len(FIX_PROJECTS)
    for idx, project in enumerate(FIX_PROJECTS, 1):
        fuzzers = project_fuzzers.get(project, [])
        print(f"\n[{idx}/{total}] {project} ({len(fuzzers)} cases)", flush=True)

        result = process_project(project, fuzzers)

        status = "OK" if result["joern_success"] else "FAIL"
        funcs = result["joern_functions"]
        edges = result["joern_edges"]
        reach = result["joern_reachability"]
        dur = result["joern_duration_sec"]

        reach_str = ", ".join(f"{k}={v}" for k, v in reach.items()) if reach else "none"
        print(f"  {status} funcs={funcs} edges={edges} dur={dur}s reach=[{reach_str}]", flush=True)

        # Update batch_results.json
        for r in d:
            if r["project"] == project:
                r["joern_success"] = result["joern_success"]
                r["joern_functions"] = result["joern_functions"]
                r["joern_edges"] = result["joern_edges"]
                r["joern_duration_sec"] = result["joern_duration_sec"]
                r["joern_reachability"] = result["joern_reachability"]
                r.setdefault("joern_error", result.get("joern_error", ""))
                break

        # Save after each project
        with open(RESULTS_FILE, "w") as f:
            json.dump(d, f, indent=2, default=str)

    print(f"\n{'='*60}")
    print(f"Done. Results saved to {RESULTS_FILE}")


if __name__ == "__main__":
    main()

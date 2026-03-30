#!/usr/bin/env python3
"""Per-project fixes for the 14 remaining NOT-OK projects.

Each project has a config specifying:
- Source directory to analyze
- Extra source files to include (fuzzers from oss-fuzz)
- Known fuzzer entry functions (for reachability tracing)
"""

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

OSSFUZZ = Path("/home/ze/oss-fuzz/projects")
WSDIR = Path("/home/ze/Z-Code-Analyzer/joern-workspace")
RESULTS_FILE = Path("/home/ze/Z-Code-Analyzer/results/batch_results.json")

# ── Per-project configurations ──────────────────────────────────────────────

PROJECTS = {
    "bad_example": {
        "repo": "https://github.com/google/oss-fuzz",
        "subdir": "projects/bad_example",  # it's inside oss-fuzz itself
        "extra_fuzzers": ["bad_example_fuzzer.cc"],
    },
    "binutils": {
        "repo": "https://github.com/bminor/binutils-gdb",
        "extra_fuzzers": ["fuzz_addr2line.c", "fuzz_nm.c"],
    },
    "boost": {
        "repo": "https://github.com/boostorg/boost",
        "extra_fuzzers": [
            "boost_graph_graphviz_fuzzer.cc", "boost_ptree_inforead_fuzzer.cc",
            "boost_ptree_iniread_fuzzer.cc", "boost_ptree_jsonread_fuzzer.cc",
            "boost_ptree_xmlread_fuzzer.cc",
        ],
    },
    "curl": {
        "repo": "https://github.com/curl/curl.git",
        "extra_fuzzers": [],  # curl's fuzzers are in curl/tests/fuzz/
        "fuzzer_search_dirs": ["tests/fuzz"],
    },
    "flatbuffers": {
        "extra_fuzzers": [],  # already in source: tests/fuzzer/
    },
    "gdal": {
        "extra_fuzzers": [],  # already in source: fuzzers/
    },
    "icu": {
        "extra_fuzzers": ["gen_unicode_string_codepage_create_fuzzer.cpp"],
        "fuzzer_search_dirs": ["icu4c/source/test/fuzzer"],
    },
    "imagemagick": {
        "repo": "https://github.com/ImageMagick/ImageMagick",
        "extra_fuzzers": ["imread_fuzzer.cc", "ping_fuzzer.cc"],
        # imagemagick oss-fuzz fuzzers are standalone, check what's in oss-fuzz dir
    },
    "libxslt": {
        "extra_fuzzers": [],  # already in source: tests/fuzz/
    },
    "llamacpp": {
        "repo": "https://github.com/ggerganov/llama.cpp",
        "fuzzer_search_dirs": ["tests/fuzz"],
    },
    "nettle": {
        "extra_fuzzers": [
            "fuzz_rsa_keypair_from_der.c", "fuzz_rsa_keypair_from_sexp.c",
            "fuzz_rsa_public_key_from_der.c", "fuzz_dsa_openssl_private_key_from_der.c",
            "fuzz_dsa_sha1_keypair_from_sexp.c", "fuzz_dsa_sha256_keypair_from_sexp.c",
        ],
    },
    "opencv": {
        "extra_fuzzers": [
            "imread_fuzzer.cc", "ping_fuzzer.cc",
        ],
        "fuzzer_search_dirs": ["modules/imgcodecs/test"],
    },
    "openssl": {
        "extra_fuzzers": [],  # fuzzers are in openssl/fuzz/
        "fuzzer_search_dirs": ["fuzz"],
    },
    "yajl-ruby": {
        "extra_fuzzers": ["json_fuzzer.c"],
    },
}


def ensure_source(project: str, config: dict) -> str | None:
    """Ensure project source is available."""
    dest = WSDIR / project
    if dest.exists() and any(dest.iterdir()):
        return str(dest)

    repo = config.get("repo")
    if not repo:
        return None

    subdir = config.get("subdir")
    if subdir:
        # Clone parent repo and use subdir
        parent = WSDIR / f"{project}-parent"
        if not parent.exists():
            subprocess.run(
                ["git", "clone", "--depth=1", repo, str(parent)],
                capture_output=True, timeout=300,
            )
        src = parent / subdir
        if src.exists():
            shutil.copytree(src, dest, dirs_exist_ok=True)
            return str(dest)
        return None

    subprocess.run(
        ["git", "clone", "--depth=1", repo, str(dest)],
        capture_output=True, timeout=300,
    )
    return str(dest) if dest.exists() else None


def copy_fuzzers(project: str, config: dict, project_dir: str):
    """Copy fuzzer sources from oss-fuzz into project dir."""
    ossfuzz_dir = OSSFUZZ / project

    # Copy explicitly listed extra fuzzers
    for fname in config.get("extra_fuzzers", []):
        src = ossfuzz_dir / fname
        dst = Path(project_dir) / fname
        if src.exists() and not dst.exists():
            shutil.copy2(src, dst)
            logger.info("  Copied fuzzer: %s", fname)

    # Also copy ALL fuzzer source files from oss-fuzz project dir
    for ext in ["*.c", "*.cc", "*.cpp"]:
        for f in ossfuzz_dir.glob(ext):
            try:
                content = f.read_text(errors="replace")
            except Exception:
                continue
            if "LLVMFuzzerTestOneInput" in content:
                dst = Path(project_dir) / f.name
                if not dst.exists():
                    shutil.copy2(f, dst)
                    logger.info("  Copied fuzzer: %s", f.name)


def run_joern_analysis(project_dir: str) -> dict:
    """Run joern-parse and extract call graph."""
    from z_code_analyzer.backends.joern_backend import JoernBackend
    backend = JoernBackend()
    result = backend.analyze(project_dir, "cpp")
    return {
        "functions": len(result.functions),
        "edges": len(result.edges),
        "cpg_path": result.metadata.get("cpg_path", ""),
    }


def compute_reachability(cpg_path: str, benchmark_fuzzers: list[str]) -> dict:
    """Compute per-fuzzer reachability using Joern with manual name resolution."""
    script = f'''
importCpg("{cpg_path}")

import scala.collection.mutable

def resolveCallees(startName: String, maxDepth: Int): Set[String] = {{
  val visited = mutable.Set[String]()
  var frontier = Set(startName)
  for (depth <- 1 to maxDepth) {{
    val next = mutable.Set[String]()
    for (fn <- frontier if !visited.contains(fn)) {{
      visited += fn
      cpg.method.name(fn).l.foreach {{ m =>
        m.call.l.foreach {{ c =>
          val full = c.methodFullName
          if (!full.startsWith("<operator>") && !full.startsWith("<operators>")) {{
            val name = if (full.contains(".")) {{
              val bc = if (full.contains(":")) full.split(":")(0) else full
              bc.split("\\\\.").last
            }} else if (full.contains("::")) {{
              full.split("::").last.split("\\\\(")(0)
            }} else {{
              full.split(":")(0)
            }}
            if (name.nonEmpty && name != "<global>") next += name
          }}
        }}
      }}
    }}
    frontier = (next -- visited).toSet
  }}
  visited.toSet - startName
}}

println("REACH_START")
cpg.method.name("LLVMFuzzerTestOneInput").l.foreach {{ m =>
  val file = m.file.name.headOption.getOrElse("")
  val directCalls = m.call.filterNot(_.methodFullName.startsWith("<operator>"))
    .filterNot(_.methodFullName.startsWith("<operators>"))
    .map(c => {{
      val full = c.methodFullName
      if (full.contains(".")) {{
        val bc = if (full.contains(":")) full.split(":")(0) else full
        bc.split("\\\\.").last
      }} else if (full.contains("::")) {{
        full.split("::").last.split("\\\\(")(0)
      }} else {{
        full.split(":")(0)
      }}
    }}).toSet.filterNot(_.isEmpty).filterNot(_ == "<global>")

  var allReach = Set[String]()
  for (fn <- directCalls) {{
    allReach ++= resolveCallees(fn, 5)
  }}
  allReach ++= directCalls
  val internal = allReach.filter(n => cpg.method.internal.name(n).size > 0)
  println(s"FUZZ|$file|${{internal.size}}")
}}
println("REACH_END")
'''

    with open("/tmp/joern_reach_fix.sc", "w") as f:
        f.write(script)

    try:
        result = subprocess.run(
            ["joern", "--script", "/tmp/joern_reach_fix.sc"],
            capture_output=True, text=True, timeout=600,
        )
    except subprocess.TimeoutExpired:
        return {}

    # Parse
    reach = {}
    for line in result.stdout.splitlines():
        if line.startswith("FUZZ|"):
            parts = line.split("|")
            if len(parts) >= 3:
                fuzz_file = parts[1]
                count = int(parts[2]) if parts[2].isdigit() else 0
                fname = Path(fuzz_file).stem
                reach[fname] = count

    # Match to benchmark fuzzers
    matched = {}
    for bfz in benchmark_fuzzers:
        best = 0
        bfz_normalized = bfz.replace("-", "_").replace(".", "_").lower()
        for fname, count in reach.items():
            fname_normalized = fname.replace("-", "_").replace(".", "_").lower()
            if bfz_normalized in fname_normalized or fname_normalized in bfz_normalized:
                best = max(best, count)
        matched[bfz] = best

    return matched


def main():
    WSDIR.mkdir(parents=True, exist_ok=True)

    d = json.load(open(RESULTS_FILE))
    project_fuzzers = {r["project"]: r.get("benchmark_fuzzers", []) for r in d}

    for project, config in sorted(PROJECTS.items()):
        bench = project_fuzzers.get(project, [])
        print(f"\n{'='*60}", flush=True)
        print(f"  {project} ({len(bench)} cases)", flush=True)
        print(f"{'='*60}", flush=True)

        t0 = time.monotonic()

        # 1. Ensure source
        project_dir = ensure_source(project, config)
        if not project_dir:
            print(f"  SKIP: no source available", flush=True)
            continue

        # 2. Copy fuzzers
        copy_fuzzers(project, config, project_dir)

        # 3. Run Joern
        try:
            analysis = run_joern_analysis(project_dir)
            print(f"  Joern: {analysis['functions']} funcs, {analysis['edges']} edges", flush=True)
        except Exception as e:
            print(f"  Joern FAILED: {e}", flush=True)
            continue

        # 4. Compute reachability
        if analysis.get("cpg_path"):
            reach = compute_reachability(analysis["cpg_path"], bench)
            print(f"  Reach: {reach}", flush=True)
        else:
            reach = {}

        dur = round(time.monotonic() - t0, 1)

        # 5. Update results
        for r in d:
            if r["project"] == project:
                r["joern_functions"] = analysis["functions"]
                r["joern_edges"] = analysis["edges"]
                r["joern_reachability"] = reach
                r["joern_success"] = True
                r["joern_duration_sec"] = dur
                break

        # Save after each project
        with open(RESULTS_FILE, "w") as f:
            json.dump(d, f, indent=2, default=str)

        all_ok = all(v > 0 for v in reach.values()) if reach else False
        status = "✅ ALL CASES OK" if all_ok else "⚠️  PARTIAL"
        print(f"  {status} ({dur}s)", flush=True)

    print(f"\n{'='*60}")
    print("Done.")


if __name__ == "__main__":
    main()

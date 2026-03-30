#!/usr/bin/env python3
"""Fix remaining 12 projects by manually specifying entry functions for Joern reachability."""

import json, subprocess, sys, time, re
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

RESULTS_FILE = Path("/home/ze/Z-Code-Analyzer/results/batch_results.json")
WSDIR = Path("/home/ze/Z-Code-Analyzer/joern-workspace")

# Per-project: benchmark_case -> list of entry functions to trace
# These are the actual functions called by LLVMFuzzerTestOneInput
PROJECT_ENTRIES = {
    "bad_example": {
        "bad_example_fuzzer": ["uncompress"],
    },
    "binutils": {
        "fuzz_addr2line": ["process_file", "xmalloc", "xstrdup"],
        "fuzz_nm": ["display_file"],
    },
    "boost": {
        "boost_graph_graphviz_fuzzer": ["read_graphviz"],
        "boost_ptree_inforead_fuzzer": ["read_info"],
    },
    "curl": {
        "fuzz_url": ["curl_url", "curl_url_set", "curl_url_get", "curl_url_cleanup"],
    },
    "flatbuffers": {
        "flatbuffers_annotator_fuzzer": ["Annotate"],
        "flatbuffers_verifier_fuzzer": ["VerifyMonsterBuffer"],
    },
    "gdal": {
        "get_jpeg2000_structure_fuzzer": ["GDALGetJPEG2000Structure", "CPLDestroyXMLNode", "CSLSetNameValue"],
        "gml_geom_import_fuzzer": ["OGR_G_CreateFromGML", "OGR_G_DestroyGeometry"],
        "osr_set_from_user_input_fuzzer": ["OSRSetFromUserInput", "OSRNewSpatialReference", "OSRDestroySpatialReference"],
        "spatialite_geom_import_fuzzer": ["OGRSQLiteImportSpatiaLiteGeometry"],
    },
    "icu": {
        "unicode_string_codepage_create_fuzzer": ["ucasemap_open", "ucasemap_close", "UnicodeString"],
    },
    "libxslt": {
        "xpath": ["xsltFuzzXPath", "xsltFuzzXPathFreeObject"],
        "xslt": ["xsltFuzzXslt", "xmlFree"],
    },
    "llamacpp": {
        "fuzz_json_to_grammar": ["json_schema_to_grammar"],
    },
    "nettle": {
        "fuzz_rsa_keypair_from_der": ["rsa_keypair_from_der", "rsa_public_key_init", "rsa_private_key_init"],
        "fuzz_rsa_keypair_from_sexp": ["rsa_keypair_from_sexp", "rsa_public_key_init", "rsa_private_key_init"],
        "fuzz_rsa_public_key_from_der": ["rsa_public_key_from_der_iterator", "rsa_public_key_init", "asn1_der_iterator_first"],
    },
    "opencv": {
        "imread_fuzzer": ["imread"],
    },
    "openssl": {
        # openssl fuzzers use FuzzerTestOneInput (not LLVMFuzzerTestOneInput directly)
        # The actual entry is in fuzz/<name>.c which calls specific OpenSSL APIs
        "acert": ["d2i_X509_ACERT", "X509_ACERT_free"],
        "asn1parse": ["ASN1_parse_dump", "BIO_new_mem_buf", "BIO_free"],
        "cms": ["d2i_CMS_ContentInfo", "CMS_ContentInfo_free"],
        "punycode": ["ossl_punycode_decode", "ossl_a2ulabel"],
        "v3name": ["X509_NAME_new", "d2i_X509_NAME", "X509_NAME_free"],
    },
    "yajl-ruby": {
        "json_fuzzer": ["yajl_alloc", "yajl_parse", "yajl_free"],
    },
}


def query_reachability(cpg_path: str, entry_functions: list[str]) -> int:
    """Query Joern for transitive reachability from given entry functions."""
    entries_scala = ", ".join(f'"{f}"' for f in entry_functions)
    script = f'''
importCpg("{cpg_path}")
import scala.collection.mutable

val entries = List({entries_scala})
val visited = mutable.Set[String]()
var frontier = entries.toSet

for (depth <- 1 to 5) {{
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

val internal = visited.filter(n => cpg.method.internal.name(n).size > 0)
println(s"REACH:${{internal.size}}")
'''
    with open("/tmp/joern_fix_reach.sc", "w") as f:
        f.write(script)

    try:
        result = subprocess.run(
            ["joern", "--script", "/tmp/joern_fix_reach.sc"],
            capture_output=True, text=True, timeout=300,
        )
        for line in result.stdout.splitlines():
            if line.startswith("REACH:"):
                return int(line.split(":")[1])
    except Exception as e:
        print(f"    Error: {e}")
    return 0


def find_cpg(project: str) -> str | None:
    """Find existing CPG for a project."""
    # Check workspace for existing CPG
    workspace = Path.home() / "joern-workspace" / "workspace"
    if not workspace.exists():
        workspace = WSDIR / "workspace"
    # Try common locations
    for pattern in [f"/tmp/joern-*.cpg", f"/home/ze/joern-workspace/*.cpg"]:
        import glob
        for p in glob.glob(pattern):
            if project in p:
                return p
    return None


def main():
    d = json.load(open(RESULTS_FILE))
    project_map = {r["project"]: r for r in d}

    for project, cases in sorted(PROJECT_ENTRIES.items()):
        r = project_map.get(project)
        if not r:
            print(f"\n{project}: NOT IN RESULTS")
            continue

        # Find or create CPG
        cpg_path = None
        joern_meta = r.get("joern_functions", 0)

        # Re-parse if needed
        source_dir = WSDIR / project
        if not source_dir.exists():
            print(f"\n{project}: NO SOURCE DIR")
            continue

        print(f"\n=== {project} ===", flush=True)

        # Parse with joern if CPG doesn't exist
        cpg_path = f"/tmp/joern-fix-{project}.cpg"
        if not Path(cpg_path).exists():
            print(f"  Parsing {source_dir}...", flush=True)
            t0 = time.time()
            result = subprocess.run(
                ["joern-parse", str(source_dir), "-o", cpg_path],
                capture_output=True, text=True, timeout=1800,
            )
            if not Path(cpg_path).exists():
                print(f"  PARSE FAILED: {result.stderr[-200:]}")
                continue
            print(f"  Parsed in {time.time()-t0:.0f}s", flush=True)
        else:
            print(f"  Using existing CPG: {cpg_path}", flush=True)

        # Query reachability for each case
        reach = {}
        for case_name, entries in cases.items():
            count = query_reachability(cpg_path, entries)
            reach[case_name] = count
            print(f"  {case_name}: entries={entries} -> reach={count}", flush=True)

        # Update results
        r["joern_reachability"] = {**r.get("joern_reachability", {}), **reach}

        # Save after each project
        with open(RESULTS_FILE, "w") as f:
            json.dump(d, f, indent=2, default=str)

        all_ok = all(v > 0 for v in reach.values())
        print(f"  {'✅ ALL OK' if all_ok else '⚠️ PARTIAL'}", flush=True)

    print("\nDone.")


if __name__ == "__main__":
    main()

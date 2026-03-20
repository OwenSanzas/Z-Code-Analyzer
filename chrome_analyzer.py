#!/usr/bin/env python3
"""Chrome dependency analyzer — analyzes each third_party lib from Chrome's compile_commands.json."""

import json
import os
import re
import shutil
import subprocess
import sys
import time
from collections import defaultdict
from pathlib import Path

import psycopg2

sys.stdout.reconfigure(line_buffering=True)
os.environ["PYTHONUNBUFFERED"] = "1"

# Config
CHROMIUM_SRC = Path("/data2/ze/chromium/src")
CC_JSON = CHROMIUM_SRC / "out" / "Default" / "compile_commands.json"
BC_DIR = Path("/data2/ze/chrome-bc")
WORKSPACE = Path("/data2/ze/Z-Code-Analyzer/workspace")
PG_DSN = "postgresql://zca:zca_pass@127.0.0.1:5433/z_code_analyzer"
NEO4J_URI = "bolt://localhost:7687"

# LLVM tools — use clang-19 (supports C++23 for Chrome's libc++ headers)
# SVF rebuilt from source against LLVM 19 for bitcode compatibility
CLANG = "/usr/bin/clang-19"
CLANGPP = "/usr/bin/clang++-19"
LLVM_LINK = "/usr/bin/llvm-link-19"

# Native SVF (no Docker needed!)
SVF_WPA = "/data2/ze/svf-build/build/bin/wpa"
SVF_EXTAPI = "/data2/ze/svf-build/build/lib/extapi.bc"
OPT = "/usr/bin/opt-19"


def get_db():
    return psycopg2.connect(PG_DSN)


def update_lib_status(lib_name, **kwargs):
    """Update a lib's status in PostgreSQL."""
    conn = get_db()
    cur = conn.cursor()
    sets = ", ".join(f"{k} = %s" for k in kwargs)
    vals = list(kwargs.values())
    vals.append(lib_name)
    cur.execute(f"UPDATE chrome_lib_analysis SET {sets}, updated_at = NOW() WHERE lib_name = %s", vals)
    if cur.rowcount == 0:
        # Insert
        cols = ", ".join(kwargs.keys()) + ", lib_name"
        placeholders = ", ".join(["%s"] * len(kwargs)) + ", %s"
        cur.execute(f"INSERT INTO chrome_lib_analysis ({cols}) VALUES ({placeholders})", vals)
    conn.commit()
    conn.close()


def parse_compile_commands():
    """Parse compile_commands.json and group by lib/component."""
    with open(CC_JSON) as f:
        entries = json.load(f)

    libs = defaultdict(list)  # lib_name -> [entries]
    out_dir = str(CHROMIUM_SRC / "out" / "Default")

    for entry in entries:
        src = entry.get("file", "")
        directory = entry.get("directory", out_dir)
        if not src:
            continue

        # Resolve relative paths (Chrome uses ../../xxx relative to out/Default)
        if not os.path.isabs(src):
            src = os.path.normpath(os.path.join(directory, src))
            # Update entry with resolved path
            entry = dict(entry)
            entry["file"] = src

        # Make path relative to chromium/src
        if src.startswith(str(CHROMIUM_SRC) + "/"):
            rel = os.path.relpath(src, CHROMIUM_SRC)
        else:
            rel = src

        # Skip non-C/C++ files
        if not any(rel.endswith(ext) for ext in ('.c', '.cc', '.cpp', '.cxx')):
            continue

        # Categorize
        parts = rel.split("/")
        if parts[0] == "third_party" and len(parts) > 1:
            lib_name = f"third_party/{parts[1]}"
        elif parts[0] == "out" and len(parts) > 3 and parts[2] == "gen":
            gen_parts = parts[3:]
            if gen_parts[0] == "third_party" and len(gen_parts) > 1:
                lib_name = f"third_party/{gen_parts[1]}"
            else:
                lib_name = f"chrome/{gen_parts[0]}"
        elif parts[0] in ("chrome", "content", "base", "net", "gpu", "media",
                          "ui", "cc", "components", "services", "mojo",
                          "ipc", "storage", "sql", "crypto", "url",
                          "skia", "v8", "sandbox", "extensions", "printing",
                          "pdf", "device", "headless", "remoting", "ash",
                          "chromeos", "apps", "gin", "google_apis",
                          "courgette", "dbus", "codelabs", "chromecast",
                          "testing", "tools", "build", "ppapi", "rlz",
                          "android_webview", "weblayer", "fuchsia_web",
                          "device", "ios"):
            lib_name = f"chrome/{parts[0]}"
        else:
            lib_name = f"other/{parts[0]}"

        libs[lib_name].append(entry)

    return dict(libs)


def _compile_one_entry(args):
    """Compile a single entry to bitcode. Used by parallel compile."""
    entry, bc_output_dir, clang, clangpp = args
    src = entry.get("file", "")
    directory = entry.get("directory", ".")

    if not os.path.isfile(src):
        return None, "skip"

    if "arguments" in entry:
        parts = list(entry["arguments"])
    elif "command" in entry:
        import shlex
        try:
            parts = shlex.split(entry["command"])
        except ValueError:
            parts = entry["command"].split()
    else:
        return None, "skip"

    flags = []
    skip_next = False
    for i, p in enumerate(parts):
        if skip_next:
            skip_next = False
            continue
        if i == 0:
            continue
        if p in ('-o', '-MF', '-MT', '-MQ', '-MJ', '-Xclang'):
            skip_next = True
            continue
        if p in ('-c', '-MD', '-MP', '-MMD'):
            continue
        if p == src or (i > 0 and os.path.basename(p) == os.path.basename(src)):
            continue
        if p.endswith(('.o', '.d')):
            continue
        # Keep -D (defines)
        if p.startswith('-D'):
            flags.append(p)
            continue
        # Keep -std
        if p.startswith('-std='):
            flags.append(p)
            continue
        # Handle -I with possible relative path
        if p.startswith('-I'):
            path = p[2:]
            if path and not os.path.isabs(path):
                path = os.path.normpath(os.path.join(directory, path))
            flags.append('-I' + path)
            continue
        # Handle -isystemPATH (no space) and -isystem PATH (with space)
        if p.startswith('-isystem'):
            path = p[len('-isystem'):]
            if path:  # -isystemPATH (no space)
                if not os.path.isabs(path):
                    path = os.path.normpath(os.path.join(directory, path))
                flags.extend(['-isystem', path])
            else:  # -isystem PATH (next arg is path, handled by skip_next logic below)
                # peek next arg
                if i + 1 < len(parts):
                    nxt = parts[i + 1]
                    if not os.path.isabs(nxt):
                        nxt = os.path.normpath(os.path.join(directory, nxt))
                    flags.extend(['-isystem', nxt])
                    skip_next = True
            continue
        # Handle -include
        if p.startswith('-include'):
            flags.append(p)
            continue

    flags = [f for f in flags if not f.startswith('-O')]
    flags.extend(['-emit-llvm', '-g', '-O0', '-w', '-Wno-everything',
                   '-fPIC', '-fno-exceptions', '-nostdinc++'])

    is_cpp = src.endswith(('.cc', '.cpp', '.cxx', '.mm'))
    compiler = clangpp if is_cpp else clang

    safe_name = os.path.relpath(src, str(CHROMIUM_SRC)).replace("/", "_")
    safe_name = re.sub(r'\.[^.]+$', '.bc', safe_name)
    bc_out = os.path.join(str(bc_output_dir), safe_name)

    try:
        result = subprocess.run(
            [compiler] + flags + ['-c', src, '-o', bc_out],
            capture_output=True, timeout=120, cwd=directory,
        )
        if result.returncode == 0 and os.path.isfile(bc_out) and os.path.getsize(bc_out) > 100:
            with open(bc_out, 'rb') as f:
                magic = f.read(2)
            if magic == b'BC':
                return bc_out, "ok"
            else:
                os.unlink(bc_out)
                return None, "skip"
        else:
            if os.path.isfile(bc_out):
                os.unlink(bc_out)
            return None, "error"
    except Exception:
        return None, "error"


def compile_lib_to_bitcode(lib_name, entries, bc_output_dir):
    """Compile a lib's source files to bitcode using compile_commands.json entries (parallel)."""
    from concurrent.futures import ProcessPoolExecutor, as_completed
    bc_output_dir.mkdir(parents=True, exist_ok=True)

    bc_files = []
    errors = 0
    skipped = 0

    # Parallel compile with N workers
    n_workers = min(os.cpu_count() or 4, 8)
    args_list = [(e, bc_output_dir, CLANG, CLANGPP) for e in entries]

    with ProcessPoolExecutor(max_workers=n_workers) as pool:
        futures = {pool.submit(_compile_one_entry, a): a for a in args_list}
        for future in as_completed(futures):
            try:
                bc_path, status = future.result()
                if status == "ok" and bc_path:
                    bc_files.append(bc_path)
                elif status == "skip":
                    skipped += 1
                else:
                    errors += 1
            except Exception:
                errors += 1

    return bc_files, errors, skipped


def compile_lib_to_bitcode_serial(lib_name, entries, bc_output_dir):
    """Compile a lib's source files to bitcode (serial fallback)."""
    bc_output_dir.mkdir(parents=True, exist_ok=True)

    bc_files = []
    errors = 0
    skipped = 0

    for entry in entries:
        src = entry.get("file", "")
        directory = entry.get("directory", ".")

        if not os.path.isfile(src):
            skipped += 1
            continue

        # Get compilation arguments
        if "arguments" in entry:
            parts = list(entry["arguments"])
        elif "command" in entry:
            import shlex
            try:
                parts = shlex.split(entry["command"])
            except ValueError:
                parts = entry["command"].split()
        else:
            skipped += 1
            continue

        # Extract only essential flags: -D (defines), -I (includes), -std, -isystem, -include
        # Skip all compiler-specific flags (clang-23 vs system clang-17 incompatibility)
        flags = []
        skip_next = False
        for i, p in enumerate(parts):
            if skip_next:
                skip_next = False
                continue
            if i == 0:  # compiler path
                continue
            if p in ('-o', '-MF', '-MT', '-MQ', '-MJ', '-Xclang'):
                skip_next = True
                continue
            if p in ('-c', '-MD', '-MP', '-MMD'):
                continue
            if p == src or (i > 0 and os.path.basename(p) == os.path.basename(src)):
                continue
            if p.endswith(('.o', '.d')):
                continue
            # Only keep essential flags
            if p.startswith(('-D', '-I', '-isystem', '-include', '-std=')):
                # Resolve relative -I paths
                if p.startswith('-I') and len(p) > 2 and not os.path.isabs(p[2:]):
                    p = '-I' + os.path.normpath(os.path.join(directory, p[2:]))
                elif p.startswith('-isystem') and '=' not in p:
                    # -isystem path (next arg or =path)
                    pass
                flags.append(p)
                continue
            # Keep -isystem with next arg
            if p == '-isystem':
                flags.append(p)
                continue

        # Add our flags (-nostdinc++ to use Chrome's bundled libc++)
        flags.extend(['-emit-llvm', '-g', '-O0', '-w', '-Wno-everything',
                       '-fPIC', '-nostdinc++'])

        # Determine C vs C++ — use Chrome's clang for compatibility
        is_cpp = src.endswith(('.cc', '.cpp', '.cxx', '.mm'))
        compiler = CLANGPP if is_cpp else CLANG
        # Also ensure the compiler path is absolute
        if not os.path.isabs(compiler):
            compiler = os.path.normpath(os.path.join(str(CHROMIUM_SRC), compiler))

        # Output path
        safe_name = os.path.relpath(src, str(CHROMIUM_SRC)).replace("/", "_")
        safe_name = re.sub(r'\.[^.]+$', '.bc', safe_name)
        bc_out = bc_output_dir / safe_name

        cmd = [compiler] + flags + ['-c', src, '-o', str(bc_out)]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=120,
                                    cwd=directory)
            if result.returncode == 0 and bc_out.exists() and bc_out.stat().st_size > 100:
                # Verify it's actually bitcode (not ELF from assembly)
                with open(bc_out, 'rb') as f:
                    magic = f.read(2)
                if magic == b'BC':
                    bc_files.append(str(bc_out))
                else:
                    bc_out.unlink(missing_ok=True)
                    skipped += 1
            else:
                bc_out.unlink(missing_ok=True)
                errors += 1
        except subprocess.TimeoutExpired:
            errors += 1
        except Exception:
            errors += 1

    return bc_files, errors, skipped


def link_bitcode(bc_files, output_path):
    """Link bitcode files into a single library.bc using tree-based batching."""
    if not bc_files:
        return False

    if len(bc_files) == 1:
        shutil.copy2(bc_files[0], output_path)
        return True

    # Try batch link first (works for small sets)
    if len(bc_files) <= 200:
        try:
            result = subprocess.run(
                [LLVM_LINK, '--suppress-warnings'] + bc_files + ['-o', str(output_path)],
                capture_output=True, timeout=600,
            )
            if result.returncode == 0 and Path(output_path).exists():
                return True
        except Exception:
            pass

    # Tree-based batch linking: merge in groups of BATCH_SIZE, then merge groups
    BATCH_SIZE = 50
    tmp_dir = Path(str(output_path) + "_link_tmp")
    tmp_dir.mkdir(parents=True, exist_ok=True)

    current_files = list(bc_files)
    level = 0

    while len(current_files) > 1:
        next_files = []
        for batch_idx in range(0, len(current_files), BATCH_SIZE):
            batch = current_files[batch_idx:batch_idx + BATCH_SIZE]
            if len(batch) == 1:
                next_files.append(batch[0])
                continue

            merged = str(tmp_dir / f"level{level}_batch{batch_idx}.bc")
            try:
                result = subprocess.run(
                    [LLVM_LINK, '--suppress-warnings'] + batch + ['-o', merged],
                    capture_output=True, timeout=300,
                )
                if result.returncode == 0 and Path(merged).exists() and Path(merged).stat().st_size > 100:
                    next_files.append(merged)
                else:
                    # Fallback: link one by one, skip failures
                    acc = batch[0]
                    for bc in batch[1:]:
                        tmp_merged = str(tmp_dir / f"level{level}_inc.bc")
                        try:
                            r = subprocess.run(
                                [LLVM_LINK, '--suppress-warnings', acc, bc, '-o', tmp_merged],
                                capture_output=True, timeout=120,
                            )
                            if r.returncode == 0:
                                acc = tmp_merged
                        except Exception:
                            pass
                    next_files.append(acc)
            except Exception:
                # On timeout, just take first file of batch
                next_files.append(batch[0])

        current_files = next_files
        level += 1

    if current_files:
        shutil.copy2(current_files[0], str(output_path))

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return Path(output_path).exists() and Path(output_path).stat().st_size > 100


def run_svf(lib_name, bc_path, output_dir):
    """Run SVF pointer analysis on bitcode (native, no Docker)."""
    bc_path = Path(bc_path)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Normalize IR with opt-19
    opt_bc = str(bc_path) + ".opt"
    try:
        result = subprocess.run(
            [OPT, "-passes=simplifycfg", "-strip-debug",
             str(bc_path), "-o", opt_bc],
            capture_output=True, timeout=300,
        )
        if result.returncode == 0 and Path(opt_bc).exists() and Path(opt_bc).stat().st_size > 100:
            shutil.move(opt_bc, str(bc_path))
    except Exception:
        pass
    Path(opt_bc).unlink(missing_ok=True)

    # Run SVF natively (no Docker!)
    svf_timeout = 3600   # 1h default
    bc_size = bc_path.stat().st_size
    if bc_size > 100_000_000:  # > 100MB
        svf_timeout = 7200   # 2h
    if bc_size > 500_000_000:  # > 500MB
        svf_timeout = 14400  # 4h

    try:
        result = subprocess.run(
            [SVF_WPA, f"-extapi={SVF_EXTAPI}",
             "-ander", "-dump-callgraph", str(bc_path)],
            capture_output=True, timeout=svf_timeout,
            cwd=str(output_dir),
        )
    except subprocess.TimeoutExpired:
        raise TimeoutError(f"SVF timed out after {svf_timeout}s")

    dot_files = list(output_dir.glob("callgraph*.dot"))
    if not dot_files:
        stderr = result.stderr.decode('utf-8', errors='replace')[-500:] if result.stderr else ""
        raise RuntimeError(f"SVF produced no callgraph DOT files. stderr: {stderr}")

    return output_dir


def parse_dot_and_import(lib_name, svf_output_dir, language="c++"):
    """Parse SVF DOT output and import to Neo4j."""
    from z_code_analyzer.svf.svf_dot_parser import (
        parse_svf_dot_file, get_all_function_names, get_typed_edge_list,
    )
    from z_code_analyzer.backends.base import FunctionRecord, CallEdge, CallType, AnalysisResult
    from z_code_analyzer.graph_store import GraphStore
    from z_code_analyzer.snapshot_manager import SnapshotManager

    svf_out = Path(svf_output_dir)
    dot_final = svf_out / "callgraph_final.dot"
    dot_initial = svf_out / "callgraph_initial.dot"

    if not dot_final.exists():
        dots = list(svf_out.glob("callgraph*.dot"))
        if not dots:
            raise RuntimeError("No callgraph DOT files")
        dot_final = dots[0]

    nodes, final_adj = parse_svf_dot_file(dot_final)
    all_funcs = get_all_function_names(nodes)

    if dot_initial.exists():
        _, initial_adj = parse_svf_dot_file(dot_initial)
        typed_edges = get_typed_edge_list(initial_adj, final_adj)
    else:
        typed_edges = [(c, e, "direct") for c, es in final_adj.items() for e in es]

    functions = []
    for fn in sorted(all_funcs):
        functions.append(FunctionRecord(
            name=fn, file_path="", start_line=0, end_line=0,
            content="", language=language, source_backend="svf-chrome",
        ))

    edges = []
    for caller, callee, ctype in typed_edges:
        edges.append(CallEdge(
            caller=caller, callee=callee,
            call_type=CallType.FPTR if ctype == "fptr" else CallType.DIRECT,
            caller_file="", callee_file="", source_backend="svf-chrome",
        ))

    internal = sum(1 for f in functions if not _is_external(f.name))
    external = sum(1 for f in functions if _is_external(f.name))

    # Import to Neo4j
    gs = GraphStore(NEO4J_URI)
    import asyncio
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    engine = create_engine(PG_DSN)
    sm = SnapshotManager(session_factory=sessionmaker(bind=engine))

    repo_url = f"chrome://{lib_name}"
    snapshot_doc = asyncio.run(sm.acquire_or_wait(repo_url, "HEAD", "svf-chrome"))
    if not snapshot_doc:
        raise RuntimeError("Failed to acquire snapshot")

    snapshot_id = str(snapshot_doc.id)
    gs.delete_snapshot(snapshot_id)
    gs.create_snapshot_node(snapshot_id, repo_url, "HEAD", "svf-chrome")

    analysis_result = AnalysisResult(
        functions=functions, edges=edges, language=language,
        backend="svf-chrome", analysis_duration_seconds=0,
        metadata={"internal_count": internal, "external_count": external},
    )

    func_count = gs.import_functions(snapshot_id, functions)
    edge_count = gs.import_edges(snapshot_id, edges)

    sm.mark_completed(snapshot_id, func_count, edge_count, [],
                      analysis_duration_sec=0, language=language)

    return {
        "snapshot_id": snapshot_id,
        "function_count": len(functions),
        "internal": internal,
        "external": external,
        "edge_count": len(edges),
    }


def _is_external(name):
    """Heuristic: external functions are typically libc/system calls."""
    # Functions without source info are external
    # For now, we'll determine this from SVF's node classification
    return False  # Will be refined based on DOT node attributes


def analyze_lib(lib_name, entries):
    """Full analysis pipeline for a single lib."""
    safe = lib_name.replace("/", "_")
    bc_dir = BC_DIR / safe
    output_dir = WORKSPACE / f"chrome-{safe}"

    t0 = time.time()
    status_update = {"status": "building", "source_file_count": len(entries)}

    try:
        update_lib_status(lib_name, **status_update)

        # Step 1: Compile to bitcode
        build_t0 = time.time()
        print(f"  [{lib_name}] Compiling {len(entries)} files to bitcode...")
        bc_files, errors, skipped = compile_lib_to_bitcode(lib_name, entries, bc_dir)
        build_dur = round(time.time() - build_t0, 1)

        if not bc_files:
            raise RuntimeError(f"No bitcode produced ({errors} errors, {skipped} skipped)")

        print(f"  [{lib_name}] Compiled: {len(bc_files)} bc, {errors} errors, {skipped} skipped ({build_dur}s)")

        # Step 2: Link bitcode
        bc_output = output_dir / "library.bc"
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"  [{lib_name}] Linking {len(bc_files)} bitcode files...")
        if not link_bitcode(bc_files, str(bc_output)):
            raise RuntimeError("llvm-link failed")

        bc_size = bc_output.stat().st_size
        print(f"  [{lib_name}] library.bc: {bc_size / 1024 / 1024:.1f}MB")

        # Clean up individual bc files
        shutil.rmtree(bc_dir, ignore_errors=True)

        # Step 3: SVF analysis
        update_lib_status(lib_name, status="svf", bitcode_size_bytes=bc_size,
                          build_duration_sec=build_dur)

        svf_t0 = time.time()
        print(f"  [{lib_name}] Running SVF analysis...")
        svf_out = run_svf(lib_name, str(bc_output), output_dir / "svf")
        svf_dur = round(time.time() - svf_t0, 1)
        print(f"  [{lib_name}] SVF complete ({svf_dur}s)")

        # Step 4: Parse and import (with retry for Neo4j flakiness)
        result = None
        for _attempt in range(3):
            try:
                result = parse_dot_and_import(lib_name, svf_out)
                break
            except Exception as neo_err:
                if "7687" in str(neo_err) or "connect" in str(neo_err).lower():
                    print(f"  [{lib_name}] Neo4j connection failed, retry {_attempt+1}/3...")
                    time.sleep(30)
                else:
                    raise
        if result is None:
            raise RuntimeError("Neo4j import failed after 3 retries")
        total_dur = round(time.time() - t0, 1)

        update_lib_status(
            lib_name,
            status="success",
            function_count=result["function_count"],
            internal_function_count=result["internal"],
            external_function_count=result["external"],
            edge_count=result["edge_count"],
            snapshot_id=result["snapshot_id"],
            bitcode_size_bytes=bc_size,
            build_duration_sec=build_dur,
            svf_duration_sec=svf_dur,
            analysis_duration_sec=total_dur,
            error=None,
        )

        print(f"  [{lib_name}] SUCCESS: {result['function_count']} fn, "
              f"{result['edge_count']} edges ({total_dur}s)")

        # Cleanup
        shutil.rmtree(output_dir, ignore_errors=True)
        return True

    except Exception as e:
        total_dur = round(time.time() - t0, 1)
        err_msg = str(e)[:500]
        update_lib_status(lib_name, status="failed", error=err_msg,
                          analysis_duration_sec=total_dur)
        print(f"  [{lib_name}] FAILED: {err_msg[:100]} ({total_dur}s)")
        # Cleanup
        shutil.rmtree(bc_dir, ignore_errors=True)
        shutil.rmtree(output_dir, ignore_errors=True)
        return False


def inventory(libs):
    """Write inventory to PostgreSQL."""
    conn = get_db()
    cur = conn.cursor()
    for lib_name, entries in sorted(libs.items()):
        cur.execute("""
            INSERT INTO chrome_lib_analysis (lib_name, source_file_count, status)
            VALUES (%s, %s, 'pending')
            ON CONFLICT (lib_name) DO UPDATE SET source_file_count = %s, updated_at = NOW()
        """, (lib_name, len(entries), len(entries)))
    conn.commit()
    conn.close()


def main():
    if not CC_JSON.exists():
        print(f"ERROR: {CC_JSON} not found. Run gn gen first.")
        sys.exit(1)

    print("Parsing compile_commands.json...")
    libs = parse_compile_commands()

    # Sort by size (smallest first for quick wins)
    sorted_libs = sorted(libs.items(), key=lambda x: len(x[1]))

    print(f"\nFound {len(sorted_libs)} components ({sum(len(v) for v in libs.values())} total files)")
    print(f"{'Component':<50} {'Files':>6}")
    print("-" * 60)
    for name, entries in sorted_libs:
        print(f"  {name:<48} {len(entries):>6}")

    # Write inventory
    print("\nWriting inventory to PostgreSQL...")
    inventory(libs)

    # Analyze each lib
    success = 0
    failed = 0
    for i, (name, entries) in enumerate(sorted_libs):
        print(f"\n[{i+1}/{len(sorted_libs)}] {name} ({len(entries)} files)")

        if len(entries) == 0:
            update_lib_status(name, status="skipped", error="no source files")
            continue

        ok = analyze_lib(name, entries)
        if ok:
            success += 1
        else:
            failed += 1

        print(f"  Progress: {success} success, {failed} failed, "
              f"{len(sorted_libs)-i-1} remaining")

    print(f"\n{'='*60}")
    print(f"COMPLETE: {success} success, {failed} failed out of {len(sorted_libs)}")


if __name__ == "__main__":
    main()

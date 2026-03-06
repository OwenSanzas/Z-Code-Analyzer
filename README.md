# Z-Code-Analyzer

Multi-backend static analysis engine for C/C++ call graph extraction and vulnerability reachability analysis.

## Overview

Z-Code-Analyzer extracts function-level call graphs from C/C++ library code, stores them in Neo4j, and checks whether vulnerable functions are reachable from fuzzer entry points. It is designed to support vulnerability impact assessment in fuzzing contexts.

## Architecture

```
CodeAnalyzer (Unified Facade)
    ├── StaticAnalysisOrchestrator (6-Phase Pipeline)
    ├── SnapshotManager (PostgreSQL + Concurrency)
    ├── GraphStore (Neo4j)
    └── ReachabilityChecker (Fuzzer-based Analysis)
```

### 6-Phase Analysis Pipeline

1. **ProjectProbe** — Detect language, build system, source files
2. **BuildCommandDetector** — Identify CMake / Autotools / Meson / Make
3. **BitcodeGenerator** — Generate LLVM bitcode via wllvm + Docker
4. **SVF Backend** — Run SVF pointer analysis, produce call graph (DIRECT + FPTR edges)
5. **AI Refinement** — Reserved for future LLM-assisted analysis
6. **Neo4j Import** — Import function nodes + call edges + compute fuzzer REACHES

## Installation

```bash
pip install -e ".[dev]"
```

### Prerequisites

- Python 3.10+
- Neo4j 5.x (for graph storage)
- PostgreSQL (for snapshot metadata)
- Docker (for SVF analysis backend)

## Usage

### CLI

```bash
# Generate a work order template
z-analyze create-work -o work.json

# Run full analysis pipeline
z-analyze run work.json --neo4j-uri bolt://localhost:7687 --pg-url postgresql://localhost/z_code_analyzer

# Quick project probe
z-analyze probe /path/to/project
```

### Python API

```python
from z_code_analyzer import CodeAnalyzer, SnapshotRequest, VulnImpactRequest

# Analyze a snapshot
result = await analyzer.analyze_snapshot(
    SnapshotRequest(
        repo_url="https://github.com/curl/curl",
        version="v7.75.0",
        fuzzer_sources={"curl_fuzz": ["fuzz/fuzz_main.c"]}
    )
)

# Check vulnerability reachability
vuln_result = await analyzer.investigate_vuln(
    VulnImpactRequest(
        client_repo_url="https://github.com/client/app",
        client_version="main",
        library_repo_url="https://github.com/curl/curl",
        library_version="v7.75.0",
        affected_functions=["curl_easy_setopt"]
    )
)
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `NEO4J_URI` | `bolt://localhost:7687` | Neo4j connection URI |
| `NEO4J_AUTH` | `none` | Neo4j auth (`none` or `user:password`) |
| `ZCA_DATABASE_URL` | `postgresql://localhost/z_code_analyzer` | PostgreSQL connection string |

## Testing

```bash
pytest
```

## Tech Stack

- **Python 3.10+**
- **Neo4j** — Function call graph storage and reachability queries
- **PostgreSQL** — Snapshot metadata and caching
- **SVF** — C/C++ pointer analysis (via Docker)
- **LLVM / wllvm** — Whole-program bitcode generation

## Documentation

See [docs/](docs/) for detailed design documentation.

## License

MIT

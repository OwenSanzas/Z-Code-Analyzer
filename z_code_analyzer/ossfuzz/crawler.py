"""OSS-Fuzz project crawler — discover and parse C/C++ projects from oss-fuzz repo.

Reads project.yaml, Dockerfile, and build.sh from each oss-fuzz/projects/<name>/
directory to extract all metadata needed for automated analysis.
"""

from __future__ import annotations

import logging
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

# Languages we support for SVF analysis
_SUPPORTED_LANGUAGES = {"c", "c++", "cpp"}

# Dockerfile patterns
_DOCKERFILE_GIT_CLONE_RE = re.compile(
    r"(?:git\s+clone|RUN\s+git\s+clone)\s+(?:--[^\s]+\s+)*"
    r"(?:(?:-b|--branch)\s+\S+\s+)?"
    r"(https?://\S+|git://\S+)"
)
_DOCKERFILE_REPO_RE = re.compile(
    r"(?:git\s+clone)\s+(?:--[^\s]+\s+)*"
    r"(?:(?:-b|--branch)\s+(\S+)\s+)?"
    r"(https?://[^\s]+?)(?:\.git)?\s"
)
_DOCKERFILE_APT_RE = re.compile(r"apt-get\s+install\s+.*?(?:\\\n|$)", re.DOTALL)


@dataclass
class FuzzerTarget:
    """A single fuzzer binary target found in build.sh."""

    name: str
    source_files: list[str] = field(default_factory=list)
    entry_point: str = "LLVMFuzzerTestOneInput"


@dataclass
class OSSFuzzProject:
    """Parsed metadata for a single oss-fuzz C/C++ project."""

    name: str
    language: str
    main_repo: str
    project_dir: str  # path to oss-fuzz/projects/<name>/
    homepage: str = ""
    primary_contact: str = ""

    # From Dockerfile
    dockerfile_repos: list[str] = field(default_factory=list)
    build_deps: list[str] = field(default_factory=list)

    # From build.sh
    fuzzer_targets: list[FuzzerTarget] = field(default_factory=list)
    build_sh_content: str = ""
    has_build_sh: bool = False

    # Docker image availability
    docker_image: str = ""
    docker_image_available: bool = False

    # Analysis readiness
    is_viable: bool = True
    skip_reason: str = ""

    @property
    def docker_image_name(self) -> str:
        """Standard oss-fuzz Docker image name."""
        return f"gcr.io/oss-fuzz/{self.name}"


class OSSFuzzCrawler:
    """Crawl oss-fuzz repository for C/C++ projects.

    Usage::

        crawler = OSSFuzzCrawler("/path/to/oss-fuzz")
        projects = crawler.crawl(limit=100)
    """

    def __init__(self, ossfuzz_path: str) -> None:
        self._root = Path(ossfuzz_path)
        self._projects_dir = self._root / "projects"
        if not self._projects_dir.is_dir():
            raise FileNotFoundError(
                f"oss-fuzz projects directory not found: {self._projects_dir}"
            )

    def crawl(
        self,
        limit: int = 100,
        require_docker_image: bool = True,
        available_images: set[str] | None = None,
    ) -> list[OSSFuzzProject]:
        """Discover C/C++ projects and return up to *limit* viable ones.

        Args:
            limit: Maximum number of projects to return.
            require_docker_image: If True, only include projects whose Docker
                image is locally available (for faster builds).
            available_images: Pre-fetched set of available Docker image names.
                If None, will query Docker for available images.

        Returns:
            List of OSSFuzzProject sorted by viability (docker-image-available first).
        """
        if available_images is None:
            available_images = self._get_available_images()

        all_projects: list[OSSFuzzProject] = []
        project_dirs = sorted(self._projects_dir.iterdir())

        for project_dir in project_dirs:
            if not project_dir.is_dir():
                continue
            project_yaml = project_dir / "project.yaml"
            if not project_yaml.exists():
                continue

            project = self._parse_project(project_dir, available_images)
            if project is None:
                continue

            all_projects.append(project)

        # Sort: docker-image-available first, then alphabetically
        all_projects.sort(
            key=lambda p: (not p.docker_image_available, p.name)
        )

        # Filter viable projects
        viable = [p for p in all_projects if p.is_viable]

        if require_docker_image:
            # Prefer projects with pre-pulled images, then add those without
            with_image = [p for p in viable if p.docker_image_available]
            without_image = [p for p in viable if not p.docker_image_available]
            result = with_image[:limit]
            if len(result) < limit:
                result.extend(without_image[: limit - len(result)])
        else:
            result = viable[:limit]

        logger.info(
            "Crawled %d C/C++ projects, %d viable, returning %d",
            len(all_projects),
            len(viable),
            len(result),
        )
        return result

    def _parse_project(
        self, project_dir: Path, available_images: set[str]
    ) -> OSSFuzzProject | None:
        """Parse a single oss-fuzz project directory."""
        name = project_dir.name
        project_yaml = project_dir / "project.yaml"

        try:
            yaml_data = yaml.safe_load(project_yaml.read_text())
        except Exception as e:
            logger.debug("Failed to parse %s/project.yaml: %s", name, e)
            return None

        if not isinstance(yaml_data, dict):
            return None

        # Check language
        language = str(yaml_data.get("language", "")).lower().strip()
        if language not in _SUPPORTED_LANGUAGES:
            return None

        # Normalize language
        if language == "cpp":
            language = "c++"

        main_repo = str(yaml_data.get("main_repo", "")).strip()
        if not main_repo:
            return None

        project = OSSFuzzProject(
            name=name,
            language=language,
            main_repo=main_repo,
            project_dir=str(project_dir),
            homepage=str(yaml_data.get("homepage", "")),
            primary_contact=str(yaml_data.get("primary_contact", "")),
        )

        # Check Docker image availability
        docker_image = project.docker_image_name
        project.docker_image = docker_image
        project.docker_image_available = docker_image in available_images

        # Parse Dockerfile
        dockerfile = project_dir / "Dockerfile"
        if dockerfile.exists():
            self._parse_dockerfile(project, dockerfile)

        # Parse build.sh
        build_sh = project_dir / "build.sh"
        if build_sh.exists():
            project.has_build_sh = True
            try:
                project.build_sh_content = build_sh.read_text()
                project.fuzzer_targets = self._parse_build_sh(
                    project.build_sh_content
                )
            except Exception as e:
                logger.debug("Failed to parse %s/build.sh: %s", name, e)
        else:
            project.is_viable = False
            project.skip_reason = "no build.sh"

        return project

    def _parse_dockerfile(self, project: OSSFuzzProject, dockerfile: Path) -> None:
        """Extract repo URLs and build deps from Dockerfile."""
        try:
            content = dockerfile.read_text()
        except Exception:
            return

        # Extract git clone URLs
        for m in _DOCKERFILE_GIT_CLONE_RE.finditer(content):
            url = m.group(1).rstrip("\\").strip()
            # Clean up URL — remove trailing .git, quotes, etc.
            url = url.strip("'\"").rstrip(".")
            if url and url not in project.dockerfile_repos:
                project.dockerfile_repos.append(url)

    @staticmethod
    def _parse_build_sh(content: str) -> list[FuzzerTarget]:
        """Extract fuzzer targets from build.sh content.

        Looks for patterns like:
            $CXX ... -o $OUT/fuzzer_name
            $CC ... -o $OUT/fuzzer_name
            cp ... $OUT/fuzzer_name
        """
        targets: list[FuzzerTarget] = []
        seen_names: set[str] = set()

        # Pattern 1: explicit compile -o $OUT/name
        compile_re = re.compile(
            r'(?:\$C(?:XX|C)|clang(?:\+\+)?|gcc|g\+\+)\s+.*?'
            r'-o\s+\$(?:OUT|out)[/\\](\w[\w.-]*)',
            re.MULTILINE,
        )
        for m in compile_re.finditer(content):
            name = m.group(1)
            if name not in seen_names:
                seen_names.add(name)
                targets.append(FuzzerTarget(name=name))

        # Pattern 2: cp/mv to $OUT/name
        cp_re = re.compile(
            r'(?:cp|mv)\s+\S+\s+\$(?:OUT|out)[/\\](\w[\w.-]*)',
            re.MULTILINE,
        )
        for m in cp_re.finditer(content):
            name = m.group(1)
            if name not in seen_names:
                seen_names.add(name)
                targets.append(FuzzerTarget(name=name))

        # Pattern 3: for loop fuzzer compilation patterns
        # e.g., for f in $SRC/*_fuzzer.c; do ... $OUT/$(basename ...)
        loop_re = re.compile(
            r'for\s+\w+\s+in\s+.*?fuzzer.*?;\s*do',
            re.MULTILINE | re.IGNORECASE,
        )
        if loop_re.search(content) and not targets:
            # Generic fuzzer pattern detected but can't extract names statically
            targets.append(FuzzerTarget(name=f"_auto_detect_"))

        return targets

    @staticmethod
    def _get_available_images() -> set[str]:
        """Query Docker for locally available oss-fuzz images."""
        try:
            result = subprocess.run(
                ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return set()
            images: set[str] = set()
            for line in result.stdout.strip().splitlines():
                line = line.strip()
                if line:
                    images.add(line)
                    # Also add without :tag for matching
                    if ":" in line:
                        images.add(line.rsplit(":", 1)[0])
            return images
        except Exception:
            return set()

    def get_project(self, name: str) -> OSSFuzzProject | None:
        """Get a single project by name."""
        project_dir = self._projects_dir / name
        if not project_dir.is_dir():
            return None
        available_images = self._get_available_images()
        return self._parse_project(project_dir, available_images)

    def list_c_cpp_projects(self) -> list[str]:
        """List all C/C++ project names (without full parsing)."""
        names: list[str] = []
        for project_dir in sorted(self._projects_dir.iterdir()):
            if not project_dir.is_dir():
                continue
            project_yaml = project_dir / "project.yaml"
            if not project_yaml.exists():
                continue
            try:
                data = yaml.safe_load(project_yaml.read_text())
                lang = str(data.get("language", "")).lower().strip()
                if lang in _SUPPORTED_LANGUAGES:
                    names.append(project_dir.name)
            except Exception:
                continue
        return names

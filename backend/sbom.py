"""
sbom.py — Dockerfile & multi-ecosystem dependency file parser
Supports:
  - Dockerfile (FROM images → package:ecosystem mapping)
  - composer.lock (PHP)
  - Cargo.toml (Rust)
  - go.sum / go.mod (Go)
  - Gemfile.lock (Ruby)
  - pom.xml (Maven/Java)
"""

import re
import json
import xml.etree.ElementTree as ET
from typing import List, Dict, Any, Tuple

from logger import logger


# ─── Dockerfile Parser ───────────────────────────────────────────────────────

def parse_dockerfile(content: str) -> Tuple[List[Dict[str, str]], str]:
    """
    Parse a Dockerfile and extract:
    - Base image (FROM) as a package to check
    - RUN apt-get install / apk add / yum install packages
    Returns (packages, ecosystem_hint)
    """
    packages = []

    # FROM image:tag  → treat image as a technology
    from_pattern = re.compile(
        r"^\s*FROM\s+(?:--platform=\S+\s+)?([^\s:@]+)(?:[:@]([^\s]+))?",
        re.IGNORECASE | re.MULTILINE,
    )
    for m in from_pattern.finditer(content):
        image = m.group(1).strip()
        tag = (m.group(2) or "").strip()
        # Skip scratch / multi-stage aliases
        if image.lower() in ("scratch", "as"):
            continue
        # Normalise: strip registry prefix (e.g. docker.io/library/nginx → nginx)
        image_name = image.split("/")[-1]
        packages.append({"name": image_name, "version": tag, "type": "docker_image"})

    # apt-get install packages
    apt = re.findall(
        r"apt(?:-get)?\s+install\s+(?:-\S+\s+)*([a-z0-9\-\.\s=]+?)(?:\\|&&|;|$)",
        content, re.IGNORECASE | re.MULTILINE
    )
    for group in apt:
        for pkg in group.split():
            pkg = pkg.strip()
            if pkg and not pkg.startswith("-") and len(pkg) > 1:
                parts = pkg.split("=", 1)
                name = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                packages.append({"name": name, "version": version, "type": "apt"})

    # apk add packages
    apk = re.findall(
        r"apk\s+add\s+(?:--\S+\s+)*([a-z0-9\-\.\s=]+?)(?:\\|&&|;|RUN|$)",
        content, re.IGNORECASE | re.MULTILINE
    )
    for group in apk:
        for pkg in group.split():
            pkg = pkg.strip()
            if pkg and not pkg.startswith("-") and len(pkg) > 1:
                parts = pkg.split("=", 1)
                name = parts[0]
                version = parts[1] if len(parts) > 1 else ""
                packages.append({"name": name, "version": version, "type": "apk"})

    return packages, "docker"


# ─── composer.lock ───────────────────────────────────────────────────────────

def parse_composer_lock(content: str) -> Tuple[List[Dict[str, str]], str]:
    packages = []
    try:
        data = json.loads(content)
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section, []):
                name = pkg.get("name", "")
                version = pkg.get("version", "").lstrip("v")
                if name:
                    packages.append({"name": name, "version": version, "type": "composer"})
    except Exception as e:
        logger.error(f"[SBOM] composer.lock parse error: {e}")
    return packages, "Packagist"


# ─── Cargo.toml ──────────────────────────────────────────────────────────────

def parse_cargo_toml(content: str) -> Tuple[List[Dict[str, str]], str]:
    packages = []
    in_deps = False
    dep_pattern = re.compile(r'^([a-z0-9_\-]+)\s*=\s*["\']?([0-9][^\s"\',}]*)?', re.IGNORECASE)
    section_pattern = re.compile(r'^\[(.+?)\]')

    for line in content.splitlines():
        line = line.strip()
        m = section_pattern.match(line)
        if m:
            sec = m.group(1).lower()
            in_deps = "dependencies" in sec
            continue
        if in_deps and not line.startswith("#"):
            dm = dep_pattern.match(line)
            if dm:
                packages.append({
                    "name": dm.group(1),
                    "version": dm.group(2) or "",
                    "type": "cargo",
                })
    return packages, "crates.io"


# ─── go.mod ──────────────────────────────────────────────────────────────────

def parse_go_mod(content: str) -> Tuple[List[Dict[str, str]], str]:
    packages = []
    in_require = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("require ("):
            in_require = True
            continue
        if in_require and stripped == ")":
            in_require = False
            continue
        # Single-line require
        m = re.match(r"require\s+(\S+)\s+(\S+)", stripped)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2).lstrip("v"), "type": "go"})
            continue
        if in_require and stripped and not stripped.startswith("//"):
            parts = stripped.split()
            if len(parts) >= 2:
                packages.append({"name": parts[0], "version": parts[1].lstrip("v"), "type": "go"})
    return packages, "Go"


# ─── Gemfile.lock ────────────────────────────────────────────────────────────

def parse_gemfile_lock(content: str) -> Tuple[List[Dict[str, str]], str]:
    packages = []
    gem_pattern = re.compile(r"^\s{4}([a-z][a-z0-9_\-]*)\s+\(([^\)]+)\)", re.IGNORECASE)
    for line in content.splitlines():
        m = gem_pattern.match(line)
        if m:
            packages.append({"name": m.group(1), "version": m.group(2), "type": "gem"})
    return packages, "RubyGems"


# ─── pom.xml ─────────────────────────────────────────────────────────────────

def parse_pom_xml(content: str) -> Tuple[List[Dict[str, str]], str]:
    packages = []
    try:
        # Strip namespace for simpler parsing
        content_clean = re.sub(r'\sxmlns[^"]*"[^"]*"', '', content)
        content_clean = re.sub(r'<\?xml[^?]*\?>', '', content_clean)
        root = ET.fromstring(content_clean)

        def find_deps(node):
            for dep in node.findall(".//dependency"):
                group = (dep.findtext("groupId") or "").strip()
                artifact = (dep.findtext("artifactId") or "").strip()
                version = (dep.findtext("version") or "").strip()
                if artifact:
                    name = f"{group}/{artifact}" if group else artifact
                    packages.append({"name": name, "version": version, "type": "maven"})

        find_deps(root)
    except Exception as e:
        logger.error(f"[SBOM] pom.xml parse error: {e}")
    return packages, "Maven"


# ─── Router ──────────────────────────────────────────────────────────────────

SUPPORTED_FILES = {
    "dockerfile":     ("Dockerfile",    "Docker Image & APT/APK"),
    "composer.lock":  ("Composer",      "PHP / Packagist"),
    "cargo.toml":     ("Cargo",         "Rust / crates.io"),
    "go.mod":         ("Go Modules",    "Go"),
    "gemfile.lock":   ("Gemfile",       "Ruby / RubyGems"),
    "pom.xml":        ("Maven",         "Java / Maven"),
    "package.json":   ("NPM",           "Node.js / npm"),
    "requirements":   ("pip",           "Python / PyPI"),
}


def detect_and_parse(filename: str, content: str) -> Tuple[List[Dict[str, str]], str, str]:
    """
    Returns (packages, ecosystem, parser_name)
    """
    fn = filename.lower()

    if "dockerfile" in fn:
        pkgs, eco = parse_dockerfile(content)
        return pkgs, eco, "Dockerfile"

    if fn == "composer.lock" or fn.endswith("/composer.lock"):
        pkgs, eco = parse_composer_lock(content)
        return pkgs, eco, "Composer"

    if fn == "cargo.toml" or fn.endswith("/cargo.toml"):
        pkgs, eco = parse_cargo_toml(content)
        return pkgs, eco, "Cargo"

    if fn == "go.mod" or fn.endswith("/go.mod"):
        pkgs, eco = parse_go_mod(content)
        return pkgs, eco, "Go Modules"

    if fn == "gemfile.lock" or fn.endswith("/gemfile.lock"):
        pkgs, eco = parse_gemfile_lock(content)
        return pkgs, eco, "Gemfile"

    if fn == "pom.xml" or fn.endswith("/pom.xml"):
        pkgs, eco = parse_pom_xml(content)
        return pkgs, eco, "Maven"

    # Fallback to existing parsers
    return [], "unknown", "unknown"

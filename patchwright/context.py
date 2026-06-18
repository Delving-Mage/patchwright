"""Cross-file context builder for taint-aware AI discovery.

The vulnerabilities that single-file scanners miss -- and that Snyk's dataflow
engine is good at -- live ACROSS files: untrusted input enters a Spring
controller, is passed to a service, which hands it to a repository that builds a
SQL string. No per-file view can see that chain.

This module assembles a BOUNDED context for a target file so the model can reason
about inter-file taint:
  * neighbor files that define or reference the target's symbols (callers/callees),
  * source markers (where untrusted input enters), and
  * sink markers (dangerous operations) found across that neighborhood.

It is heuristic and language-agnostic (regex/string ops, no parser), tuned to stay
within a token budget. Defensive only: it locates risky data flow to fix it.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field

CODE_EXTS = (".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".kt", ".go",
             ".rb", ".php", ".cs", ".scala")
_SKIP_DIRS = (".git", "node_modules", "venv", ".venv", "dist", "build",
              "target", ".gradle", "__pycache__", "vendor")

# Where untrusted data ENTERS (sources) -- Spring-heavy but broadly useful.
SOURCE_MARKERS = (
    "@RequestParam", "@PathVariable", "@RequestBody", "@RequestHeader",
    "@CookieValue", "getParameter", "getHeader", "getInputStream",
    "HttpServletRequest", "request.", "req.", "input(", "argv", "os.environ",
    "request.args", "request.form", "request.json", "params[", "req.query",
    "req.body", "req.params",
)
# Dangerous operations data should never reach un-sanitized (sinks).
SINK_MARKERS = (
    "Statement", "createQuery", "createNativeQuery", "executeQuery", "executeUpdate",
    "Runtime.getRuntime", "ProcessBuilder", "exec(", "eval(", "ObjectInputStream",
    "readObject", "new File(", "Files.", "FileInputStream", "RestTemplate",
    "HttpClient", "URL(", "openConnection", "load(", "loads(", "subprocess",
    "os.system", "pickle", "yaml.load", "deserialize", "Cipher.getInstance",
    "MessageDigest.getInstance", "TransformerFactory", "DocumentBuilderFactory",
)

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]{2,}")
# class/def/func/method definitions worth treating as "symbols this file owns"
_DEF = re.compile(
    r"\b(?:class|interface|enum|def|func|function|public|private|protected|static)\b[^\n;{(]*?"
    r"\b([A-Z][A-Za-z0-9_]+|[a-z_][A-Za-z0-9_]+)\s*[\({:]")


@dataclass
class FileContext:
    rel: str
    code: str
    neighbors: list[tuple[str, str]] = field(default_factory=list)  # (rel, snippet)
    sources: list[str] = field(default_factory=list)
    sinks: list[str] = field(default_factory=list)

    def render(self, max_neighbor_bytes: int) -> str:
        parts = [f"=== TARGET FILE: {self.rel} ===\n{self.code}"]
        if self.sources:
            parts.append("Untrusted-input sources seen nearby: " + ", ".join(sorted(set(self.sources))[:12]))
        if self.sinks:
            parts.append("Dangerous sinks seen nearby: " + ", ".join(sorted(set(self.sinks))[:12]))
        for rel, snippet in self.neighbors:
            parts.append(f"=== RELATED FILE: {rel} (excerpt) ===\n{snippet[:max_neighbor_bytes]}")
        return "\n\n".join(parts)


def _markers_in(text: str, markers) -> list[str]:
    return [m for m in markers if m in text]


def _symbols(code: str) -> set[str]:
    syms = set(_DEF.findall(code))
    # also treat Capitalized identifiers (class/type names) as linkable symbols
    syms |= {t for t in _IDENT.findall(code) if t[:1].isupper() and len(t) >= 4}
    # drop ultra-common noise
    return {s for s in syms if s not in {
        "String", "Object", "List", "Map", "Integer", "Override", "Exception",
        "System", "Test", "Service", "Controller", "Repository", "Entity"}}


def _iter_source_files(repo_path: str):
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
        for fn in files:
            if fn.lower().endswith(CODE_EXTS):
                yield os.path.join(root, fn)


def build_file_context(repo_path: str, rel: str, max_neighbors: int = 3,
                       max_bytes: int = 16000, neighbor_bytes: int = 3000) -> FileContext | None:
    target_abs = os.path.join(repo_path, rel)
    try:
        with open(target_abs, errors="ignore") as fh:
            code = fh.read(max_bytes)
    except OSError:
        return None

    ctx = FileContext(rel=rel, code=code)
    ctx.sources = _markers_in(code, SOURCE_MARKERS)
    ctx.sinks = _markers_in(code, SINK_MARKERS)

    target_syms = _symbols(code)
    if not target_syms:
        return ctx

    # rank other files by how many of the target's symbols they reference, and
    # bonus if they carry sources/sinks (more likely to complete a taint path).
    scored: list[tuple[int, str, str]] = []
    for path in _iter_source_files(repo_path):
        if os.path.abspath(path) == os.path.abspath(target_abs):
            continue
        try:
            with open(path, errors="ignore") as fh:
                other = fh.read(max_bytes)
        except OSError:
            continue
        overlap = sum(1 for s in target_syms if s in other)
        if overlap == 0:
            continue
        bonus = (1 if _markers_in(other, SOURCE_MARKERS) else 0) + \
                (1 if _markers_in(other, SINK_MARKERS) else 0)
        nrel = os.path.relpath(path, repo_path)
        scored.append((overlap + bonus, nrel, other))
        # collect sources/sinks from the neighborhood too
        ctx.sources += _markers_in(other, SOURCE_MARKERS)
        ctx.sinks += _markers_in(other, SINK_MARKERS)

    scored.sort(key=lambda t: t[0], reverse=True)
    ctx.neighbors = [(nrel, snippet[:neighbor_bytes]) for _score, nrel, snippet in scored[:max_neighbors]]
    return ctx

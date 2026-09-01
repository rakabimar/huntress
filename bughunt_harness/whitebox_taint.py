"""Truthful multi-language local taint depth labels; Semgrep/CodeQL stay authoritative."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class TaintObservation:
    language: str
    category: str
    source: str
    sink: str
    line: int
    level: str
    sanitized: bool
    confidence: float


class MultiLanguageTaintAnalyzer:
    SOURCES = {
        "typescript": r"(?:req\.(?:body|query|params)|request\.(?:body|query)|ctx\.(?:request|params))",
        "javascript": r"(?:req\.(?:body|query|params)|request\.(?:body|query)|ctx\.(?:request|params))",
        "java": r"(?:getParameter\(|@RequestParam|@PathVariable)",
        "kotlin": r"(?:call\.parameters|receive<|@RequestParam)",
        "go": r"(?:r\.URL\.Query\(|mux\.Vars\(|c\.(?:Query|Param)\()",
        "php": r"(?:\$_GET|\$_POST|\$_REQUEST)",
    }
    SINKS = {
        "ssrf": r"(?:fetch\(|axios\.|http\.(?:Get|NewRequest)|URL\(|openConnection\(|curl_exec)",
        "sql": r"(?:executeQuery\(|\.query\(|db\.(?:Query|Exec)\(|mysqli_query|PDO\()",
        "command": r"(?:exec\(|spawn\(|Runtime\.getRuntime|ProcessBuilder|os\.Exec|shell_exec)",
        "path": r"(?:readFile\(|File\(|os\.Open\(|file_get_contents)",
        "template": r"(?:render\(|executeTemplate|template\.Execute)",
        "deserialization": r"(?:ObjectInputStream|unserialize\(|gob\.NewDecoder|JSON\.parse)",
    }
    SANITIZERS = re.compile(r"(?i)(?:sanitize|validate|allowlist|whitelist|url\.parse|filepath\.Clean|canonical)")

    def analyze(self, text: str, language: str) -> list[TaintObservation]:
        language = language.lower(); source_pattern = self.SOURCES.get(language)
        if not source_pattern: return []
        parser_confirmed = _tree_sitter_parses(text, language)
        lines = text.splitlines(); observations = []
        tainted_vars: set[str] = set()
        sanitized_vars: set[str] = set()
        for number, line in enumerate(lines, 1):
            assignment = re.search(r"(?:const|let|var|String|int)?\s*([A-Za-z_]\w*)\s*(?::=|=)\s*(.*)", line)
            if re.search(source_pattern, line):
                if assignment: tainted_vars.add(assignment.group(1))
            elif assignment and any(re.search(rf"\b{re.escape(var)}\b", assignment.group(2)) for var in tainted_vars):
                tainted_vars.add(assignment.group(1))
                if self.SANITIZERS.search(assignment.group(2)):
                    sanitized_vars.add(assignment.group(1))
            for category, sink in self.SINKS.items():
                if re.search(sink, line) and (re.search(source_pattern, line) or any(re.search(rf"\b{re.escape(var)}\b", line) for var in tainted_vars)):
                    sanitized = bool(
                        self.SANITIZERS.search(line)
                        or any(re.search(rf"\b{re.escape(var)}\b", line) for var in sanitized_vars)
                    )
                    # Regex supplies curated source/sink vocabulary and compact
                    # assignment propagation, but LEVEL_1 is reserved for a
                    # syntactically valid parser-backed local flow. Environments
                    # without the parser report only co-location depth.
                    level = "LEVEL_1" if parser_confirmed else "LEVEL_0"
                    observations.append(TaintObservation(language, category, "remote input", line.strip()[:160], number, level, sanitized, .35 if sanitized else (.7 if parser_confirmed else .45)))
        return observations

    @staticmethod
    def confirmed_level(*, semgrep_confirmed: bool = False, codeql_confirmed: bool = False, local_flow: bool = False) -> str:
        if codeql_confirmed: return "LEVEL_3"
        if semgrep_confirmed: return "LEVEL_2"
        if local_flow: return "LEVEL_1"
        return "LEVEL_0"


def _tree_sitter_parses(text: str, language: str) -> bool:
    aliases = {"typescript": "typescript", "javascript": "javascript", "java": "java", "kotlin": "kotlin", "go": "go", "php": "php"}
    try:
        from tree_sitter_language_pack import get_parser
        tree = get_parser(aliases[language]).parse(text.encode("utf-8", errors="replace"))
        return not tree.root_node.has_error
    except Exception:
        return False


__all__ = ["MultiLanguageTaintAnalyzer", "TaintObservation"]

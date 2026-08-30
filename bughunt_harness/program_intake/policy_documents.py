"""Bounded, non-executing extraction for official linked policy documents."""

from __future__ import annotations

import hashlib
import html
import io
import json
import re
import shutil
import subprocess
import tempfile
from html.parser import HTMLParser
from pathlib import Path

from .fetcher import IntakeFetchError

MAX_POLICY_DOCUMENT_BYTES = 10 * 1024 * 1024
MAX_EXTRACTED_TEXT = 2 * 1024 * 1024


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True); self.parts: list[str] = []
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag.lower() in {"script", "style", "noscript", "template"}: self.ignored += 1

    def handle_endtag(self, tag):
        if tag.lower() in {"script", "style", "noscript", "template"} and self.ignored: self.ignored -= 1

    def handle_data(self, data):
        if not self.ignored and data.strip(): self.parts.append(data.strip())


def _pdf_text(raw: bytes) -> tuple[str, dict]:
    def page_count(source: Path | None = None) -> tuple[int | None, str]:
        """Read PDF metadata without confusing ``/Page`` and ``/Pages``.

        pypdf works directly from the bounded in-memory document.  ``pdfinfo``
        is a portable fallback for installations that intentionally use the
        Poppler command-line tools without the optional Python dependency.
        Unknown is represented as ``None``; page counts are never guessed from
        PDF object bytes.
        """
        try:
            from pypdf import PdfReader  # type: ignore

            reader = PdfReader(io.BytesIO(raw), strict=False)
            if reader.is_encrypted:
                return None, "encrypted"
            return len(reader.pages), "pypdf"
        except ImportError:
            pass
        except Exception:
            return None, "pypdf-error"
        pdfinfo = shutil.which("pdfinfo")
        if pdfinfo and source is not None:
            completed = subprocess.run(
                [pdfinfo, str(source)], capture_output=True, text=True,
                timeout=15, check=False,
                env={"PATH": str(Path(pdfinfo).parent), "HOME": str(source.parent)},
            )
            if completed.returncode == 0:
                match = re.search(r"^Pages:\s*(\d+)\s*$", completed.stdout, re.MULTILINE)
                if match:
                    return int(match.group(1)), "pdfinfo"
        return None, "unavailable"

    binary = shutil.which("pdftotext")
    if binary:
        with tempfile.TemporaryDirectory(prefix="bughunt-policy-") as tmp:
            source, output = Path(tmp) / "policy.pdf", Path(tmp) / "policy.txt"
            source.write_bytes(raw)
            completed = subprocess.run(
                [binary, "-layout", "-nopgbrk", str(source), str(output)],
                capture_output=True, text=True, timeout=30, check=False,
                env={"PATH": "/usr/bin:/bin", "HOME": tmp},
            )
            if completed.returncode == 0 and output.is_file():
                text = output.read_text(encoding="utf-8", errors="replace")
                count, count_parser = page_count(source)
                return text, {
                    "parser": "pdftotext", "page_count": count,
                    "page_count_parser": count_parser,
                }
    try:
        from pypdf import PdfReader  # type: ignore
        reader = PdfReader(io.BytesIO(raw), strict=False)
        if reader.is_encrypted:
            raise IntakeFetchError("encrypted policy PDFs are not interpreted", category="policy_parser")
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        return text, {
            "parser": "pypdf", "page_count": len(reader.pages),
            "page_count_parser": "pypdf",
        }
    except ImportError as exc:
        raise IntakeFetchError("PDF policy extraction requires pypdf or pdftotext", category="policy_parser") from exc
    except IntakeFetchError:
        raise
    except Exception as exc:
        raise IntakeFetchError("official PDF has no safely extractable text", category="policy_parser") from exc


def extract_policy_document(raw: bytes, *, content_type: str = "", suffix: str = "") -> tuple[str, dict]:
    if len(raw) > MAX_POLICY_DOCUMENT_BYTES:
        raise IntakeFetchError("official policy document exceeds size limit", category="policy_parser")
    mime = content_type.split(";", 1)[0].strip().lower()
    ext = suffix.lower()
    if mime == "application/pdf" or ext == ".pdf" or raw.startswith(b"%PDF-"):
        text, metadata = _pdf_text(raw)
    elif mime in {"application/json", "text/json"} or ext == ".json":
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise IntakeFetchError("official JSON policy is invalid", category="policy_parser") from exc
        text, metadata = json.dumps(value, ensure_ascii=False, indent=2), {"parser": "json"}
    elif mime in {"text/html", "application/xhtml+xml"} or ext in {".html", ".htm"}:
        parser = _TextExtractor(); parser.feed(raw.decode("utf-8", "replace"))
        text, metadata = "\n".join(parser.parts), {"parser": "html.parser"}
    elif mime.startswith("text/") or ext in {".txt", ".md", ".markdown"}:
        text, metadata = raw.decode("utf-8", "replace"), {"parser": "utf-8-text"}
    else:
        raise IntakeFetchError("unsupported official policy document type", category="policy_parser")
    text = html.unescape(text).replace("\x00", "")
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{4,}", "\n\n\n", text).strip()
    if not text:
        raise IntakeFetchError("official policy document extracted no text", category="policy_parser")
    truncated = len(text.encode("utf-8")) > MAX_EXTRACTED_TEXT
    text = text.encode("utf-8")[:MAX_EXTRACTED_TEXT].decode("utf-8", "ignore")
    metadata.update({
        "parsed": True, "content_type": mime or "unknown", "raw_bytes": len(raw),
        "extracted_text_hash": hashlib.sha256(text.encode("utf-8")).hexdigest(),
        "truncated": truncated, "javascript_executed": False, "attachments_executed": False,
    })
    return text, metadata


__all__ = ["MAX_POLICY_DOCUMENT_BYTES", "extract_policy_document"]

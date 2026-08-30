import subprocess

from bughunt_harness.program_intake import policy_documents
from bughunt_harness.program_intake.policy_documents import extract_policy_document
from bughunt_harness.program_intake.adapters.hackerone import HackerOneAdapter
from bughunt_harness.program_intake.fetcher import FetchResult
from bughunt_harness.program_intake.provenance import SnapshotWriter


def test_html_json_markdown_policy_extraction_is_bounded_and_nonexecuting():
    html_text, html_meta = extract_policy_document(
        b"<html><script>grantAll()</script><body>Automation is forbidden.</body></html>",
        content_type="text/html",
    )
    json_text, json_meta = extract_policy_document(b'{"rule":"no destructive testing"}', content_type="application/json")
    md_text, md_meta = extract_policy_document(b"# Rules\nNo brute force.", suffix=".md")
    assert "grantAll" not in html_text and "Automation is forbidden" in html_text
    assert "no destructive testing" in json_text and "No brute force" in md_text
    assert all(item["parsed"] and not item["javascript_executed"] for item in (html_meta, json_meta, md_meta))


def test_hackerone_linked_policy_is_extracted_once_with_provenance(tmp_path):
    class Fetcher:
        def get(self, url, headers=None):
            return FetchResult(url=url, status_code=200,
                               body=b"<html><body>No automated scanning.</body></html>",
                               headers={"Content-Type": "text/html"})
    snapshot = SnapshotWriter(tmp_path, "IMP-001")
    text = HackerOneAdapter()._fetch_linked_policy_documents(
        "See https://hackerone.com/rules.html and https://attacker.invalid/ignore.pdf",
        Fetcher(), snapshot,
    )
    assert "No automated scanning" in text
    assert len(snapshot.sources) == 2
    assert snapshot.sources[-1].metadata["parsed"] is True
    assert snapshot.sources[-1].source_identifier == "https://hackerone.com/rules.html"


def _one_page_pdf() -> bytes:
    stream = b"BT /F1 12 Tf 72 720 Td (No destructive testing.) Tj ET"
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
        b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream",
    ]
    raw = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for index, body in enumerate(objects, 1):
        offsets.append(len(raw)); raw.extend(f"{index} 0 obj\n".encode() + body + b"\nendobj\n")
    xref = len(raw); raw.extend(f"xref\n0 {len(objects)+1}\n".encode())
    raw.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]: raw.extend(f"{offset:010d} 00000 n \n".encode())
    raw.extend(f"trailer\n<< /Size {len(objects)+1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode())
    return bytes(raw)


def test_pdf_policy_pypdf_path_uses_real_page_metadata(monkeypatch):
    monkeypatch.setattr(policy_documents.shutil, "which", lambda _name: None)
    text, metadata = extract_policy_document(_one_page_pdf(), content_type="application/pdf")
    assert "No destructive testing" in text
    assert metadata["parser"] == "pypdf" and metadata["page_count"] == 1
    assert metadata["page_count_parser"] == "pypdf"
    assert metadata["javascript_executed"] is False and metadata["attachments_executed"] is False


def test_pdf_policy_pdftotext_path_does_not_count_pages_objects(monkeypatch):
    def fake_which(name):
        return f"/fixture/{name}" if name == "pdftotext" else None

    def fake_run(argv, **_kwargs):
        # The command's last argument is the bounded temporary output file.
        from pathlib import Path

        Path(argv[-1]).write_text("No destructive testing.\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")

    monkeypatch.setattr(policy_documents.shutil, "which", fake_which)
    monkeypatch.setattr(policy_documents.subprocess, "run", fake_run)
    text, metadata = extract_policy_document(_one_page_pdf(), content_type="application/pdf")
    assert "No destructive testing" in text
    assert metadata["parser"] == "pdftotext"
    assert metadata["page_count"] == 1
    assert metadata["page_count_parser"] == "pypdf"

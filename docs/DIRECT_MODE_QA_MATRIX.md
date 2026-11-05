# Direct-mode protection quality and failure matrix

**Run date:** 2 November 2026. This is a synthetic regression corpus and targeted live smoke test, **not** a statistically representative accuracy benchmark. Do not convert these pass/fail observations into a single “detection accuracy” percentage.

| Input / condition | Evidence exercised | Current result / limit |
|---|---|---|
| TXT, CSV, Markdown, JSON with synthetic NRIC and email | `tests/test_direct_corpus.py` calls the direct engine and checks protected bytes and JSON validity | Both detected values absent; same-format output returned. Other structures and encodings still need a broader corpus. |
| Two-page text PDF | `tests/test_direct_corpus.py`; PDF output re-opened page by page | Detected NRIC absent on both pages; PDF metadata cleared. This does not cover arbitrary PDF layouts. |
| JPEG/PNG OCR geometry | `tests/test_ocr_redaction_safety_margin.py`, `tests/test_format_preserving_redaction.py`, `tests/test_transient_processing.py` | Synthetic skewed geometry, invalid geometry, missing values, low-confidence fields, source EXIF and output verification exercised. OCR-provider accuracy on all camera conditions is unproven. |
| Indonesian KTP aligned fields | `tests/test_ocr_redaction_safety_margin.py` and manual visual review of an example image | Separate strips, mandatory NIK protection and selective name/address KEEP paths checked. A different card layout may need manual review or fail closed. |
| PDF attachments | `tests/test_format_preserving_redaction.py` | Blocks processing rather than returning a file that could conceal an unredacted attachment. |
| KEEP email + REDACT NRIC | `tests/test_transient_processing.py` | Receipt identifies email as kept, NRIC as redacted; protected bytes retain only the selected email. This output must never be called PII-free. |
| Oversize, malformed image/JSON, oversized protected output | `tests/test_transient_processing.py` | Rejects the request before issuing a file. |
| Textract network failure and quota failure | API tests in `tests/test_transient_processing.py` | 503/429; no source bytes in response and no protected file. |
| Interrupted browser request and blocked download | `tests/customer_workflow.test.cjs` | No download on failure; download link remains available after a successful response. Browser popup/download policies can still prevent automatic saving. |

## Known gaps and next measured evaluation

The corpus does not establish precision/recall for low-resolution photocopies, oblique photos, severe blur, glare, mixed scripts, handwritten text, multi-column tables, 3 MiB scan-heavy PDFs, or p95/p99 latency under concurrent demand. A proper study needs consented or synthetic labelled documents by **format, language, category and image condition**, with page-level ground truth. Report false negatives, false positives, rejection rate, processing latency and cost separately. A rejected uncertain file counts as a safe refusal, not a successful redaction. The current Learner Lab route is throttled and has a 30-second Lambda timeout; it is not a production load benchmark.

## Reproduce the local checks

```powershell
.\.venv\Scripts\ruff.exe check src scripts tests
.\.venv\Scripts\python.exe -m pytest -q
node --test tests/customer_workflow.test.cjs
```

Use synthetic inputs for public demos. If a new real document is assessed with permission, do not commit the source or any protected copy; record only aggregate test outcomes without values or full filenames.

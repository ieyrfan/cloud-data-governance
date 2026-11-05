# DataSentinel PII intelligence engine

For a bilingual explanation of direct processing, AWS service roles, and the
documented claim boundaries, see the
[direct-mode brief](DATASENTINEL_DIRECT_MODE_BRIEF_BM_EN.md).

## Purpose

DataSentinel uses a layered local detector to find sensitive data in extracted text before a protected copy is created. It is a data-classification and loss-prevention control, not an identity-verification service and not a guarantee that every possible form of PII will be found.

The protected-document path remains fail-closed: when a required PDF redaction cannot locate every detected value, classification fails instead of publishing an unsafe copy.

## Detection flow

1. **Unicode-safe normalization** converts full-width and unusual punctuation, removes zero-width characters, and retains a normalized-to-source offset map.
2. **Deterministic candidates** find structured emails, Malaysian NRIC candidates, global phone candidates, payment cards, network identifiers, coordinates, credentials, tokens and private-key blocks.
3. **Field semantics** generates aliases from person, employment, education, health, financial, travel and government concepts instead of maintaining a pattern dump. Strong schema context can classify an unknown-country identifier without claiming that its jurisdiction has been validated.
4. **Structure grammar** relates labels and values in plain text, JSON, CSV, HTML, XML, YAML-like records, logs, database-style fields, tables and multiline/OCR-like layouts.
5. **Flexible formatting** tolerates spaces, line breaks, dots, slashes, hyphens, full-width punctuation, Unicode field names and OCR-style separation.
6. **Global fallback detection** supports generic passports, national IDs, employee/staff IDs, student IDs, patient IDs, customer/member IDs, driving licences, visas, permits, tax IDs, international phone numbers, international addresses and culturally varied names when field evidence is strong.
7. **Validation** checks calendar-valid NRIC dates, DOB dates, IP addresses, GPS ranges and Luhn-valid payment-card candidates. Country validators improve certainty but do not erase a high-quality generic contextual finding.
8. **Negative evidence** suppresses build, invoice, request, project, product, count and timestamp fields that resemble person identifiers but are not PII.
9. **Overlap resolution** retains a high-confidence specific entity instead of returning duplicate generic matches for the same span.
10. **Cross-signal correlation** raises confidence when independent PII categories form a nearby record.
11. **Risk scoring** produces severity counts, category counts, PII density, record clusters and a document risk score.
12. **Value minimisation** keeps raw values inside the classifier/redactor. Stored API intelligence and safe debug traces contain masked previews, offsets, reasons, rule IDs and validation status only.

## Result contract

Each public finding records:

- entity type and subtype;
- category and configurable severity;
- confidence from actual detector signals;
- masked preview;
- original character span, line and column;
- context label;
- detection methods;
- validation state (`VALID`, `PLAUSIBLE`, `SUSPICIOUS` or `INVALID` where relevant);
- country only when it can be supported;
- rule ID and plain-language explanation.

An invalid structured candidate can remain explainable internally but is not promoted into the redaction map. Generic passport values use `GENERIC_PASSPORT_IDENTIFIER` unless a reliable country validator exists.

## Privacy boundary

- Raw PII is not included in public findings, application logs, exceptions or frontend telemetry.
- Names remain visible in reviewer copies by the current product policy; all other supported findings are redacted.
- Amazon Textract is used only when OCR is required and enabled in the deployed AWS account.
- Amazon Comprehend is disabled by default in the Learner Lab deployment.
- Unlabelled UUIDs and private/local IP addresses are suppressed unless personal or account context supports classification.

## Evaluation

The checked-in benchmark at `tests/fixtures/pii_benchmark.json` contains synthetic data only. On 27 October 2026, its 29 annotated cases produced:

| Metric | Result |
|---|---:|
| True-positive entity labels | 24 |
| False positives | 0 |
| False negatives | 0 |
| True-negative records | 5 |
| Precision | 1.0000 |
| Recall | 1.0000 |
| F1 | 1.0000 |
| Negative-record false-positive rate | 0.0000 |

These figures describe this small regression corpus only. They are not a claim of universal or real-world 100% accuracy. Expand the annotated corpus with representative, consented, non-production samples before using the metric for production acceptance.

The global field/structure evaluation added on 28 October 2026 records the exact pre-change snapshot and current result separately:

| Evaluation | Positive cases detected | Positive cases | Negative cases with findings | Recall |
|---|---:|---:|---:|---:|
| Pre-change measured subset | 4 | 24 | 0 | 0.1667 |
| Current global synthetic corpus | 36 | 36 | 0 of 5 | 1.0000 |
| Generated mutation sample | 1,200 | 1,200 | n/a | 1.0000 |

The global corpus covers Malaysia-, Singapore-, Indonesia-, India-, China-, Japan-, Korea-, UK-, EU-, US-, Canada-, Australia-, Middle-East- and unknown-country-like synthetic records. Format groups cover plain text, JSON, CSV, HTML, XML, YAML-like records, logs, database fields, tables, multiline fields, Unicode variants and OCR-like splits. Full per-entity, per-region and per-format results are written to `output/pii-global-evaluation.json`.

These perfect values apply only to the checked-in synthetic regression and mutation samples. They are evidence that the intended variations work, not a production accuracy or universal detection claim.

Run it with:

```powershell
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\evaluate_pii_engine.py tests\fixtures\pii_benchmark.json
.\.venv\Scripts\python.exe scripts\evaluate_global_pii_engine.py
```

## Performance

The local benchmark performs normalization and scans a synthetic identifier at the start, middle and end of each payload. Offset maps use a packed unsigned-integer buffer rather than one Python integer object per character.

| Input | Time | Throughput | Peak traced memory |
|---:|---:|---:|---:|
| 1 KB | 0.0232 s | 0.04 MB/s | 0.06 MB |
| 100 KB | 0.1887 s | 0.53 MB/s | 1.65 MB |
| 1 MB | 1.8687 s | 0.54 MB/s | 16.28 MB |
| 10 MB | 20.1362 s | 0.50 MB/s | 162.86 MB |

Each payload contains a synthetic identifier at the start, middle and end; all three positions were detected at every size. The live upload workflow currently accepts at most 5 MB and caps extracted text at 1,000,000 characters. The 10 MB result characterizes the engine outside that workflow, not the deployed upload limit. Measurements vary by machine and should be treated as a regression baseline, not a service-level objective.

Run it with:

```powershell
$env:PYTHONPATH='.'
.\.venv\Scripts\python.exe scripts\benchmark_pii_engine.py
```

## Adding a detector

1. Add concept components or a safe negative field in `src/pii_engine/field_semantics.py`.
2. Add a structure adapter only when the generic grammar in `src/pii_engine/structure.py` cannot preserve the value relationship and source offsets.
3. Implement a candidate validator in `src/pii_engine/engine.py`; keep generic format discovery separate from country validation.
4. Assign category, severity, rule ID and masked preview behavior.
5. Add standard, alternate, malformed, ambiguous, negative, mutation and holdout synthetic cases.
6. Add the public entity-to-redaction mapping when the entity should be removed from protected copies.
7. Run lint, the full test suite, both synthetic evaluations, the performance benchmark, protected-file QA and live release acceptance.

## Known boundaries

- Unlabelled unknown identifiers remain ambiguous and are intentionally not promoted merely because they are alphanumeric.
- Names use strong field context and Unicode-aware shape detection; free-text global name recognition remains intentionally conservative.
- Passport, licence, tax, payroll and organisation-issued identifiers without reliable universal formats are context-scored rather than presented as officially validated formats.
- Country-specific checksum validation is not implemented for every jurisdiction. Such findings are reported as generic or plausible, not officially verified.
- OCR accuracy is bounded by source-image quality. Low-confidence or incomplete Textract extraction fails closed for review.
- A compact synthetic benchmark cannot represent all languages, layouts, obfuscation strategies or document types.
- Malware enforcement remains dependent on the configured GuardDuty Malware Protection integration; the Learner Lab template does not claim that external control is active when it is unavailable.

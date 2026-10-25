# Full-dataset usage and cost report

Run recorded: local `python3 -B code/main.py`, which produced the final root `output.csv` with 518 requests. The implementation is deterministic Python with local PDF/image extraction and OCR; it does not call an AI model, hosted inference provider, or paid API.

| Measure | Actual run |
|---|---:|
| Model provider/name | None (no generative model used) |
| Model calls | 0 |
| Input tokens | 0 |
| Output tokens | 0 |
| Total tokens | 0 |
| Average tokens per request (518) | 0 |
| Estimated model/API cost | $0.00 total; $0.00 per request |

Screenshot OCR was performed locally with Tesseract 5.5.3 via `pytesseract`; PDF text extraction used PyMuPDF 1.26.5. Neither is an LLM and neither reports model tokens. Local compute and package-install costs are not included in model/API cost; no paid service was used.

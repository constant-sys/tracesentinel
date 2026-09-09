# Contributing

Python 3.11+; no runtime dependencies. Run `python -m unittest discover -s tests -v` before submitting changes, then reproduce the README demo.

For a rule change include: trigger condition, grouping/window semantics, a positive and negative fixture, false-positive discussion, and evidence expectations. For an adapter change include supported formats and explicit parse-failure behavior.

Use synthetic or carefully sanitized fixtures only. Do not commit credentials, real user logs, generated production reports or unrelated files. Keep generated output in `output/` and local input in `data/`.

Describe what changed and the checks actually performed. Record remaining limits. AI-assisted contributions are welcome; the contributor must review and understand the result. Do not invent benchmarks or detection-accuracy claims.

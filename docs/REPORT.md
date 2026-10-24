# SecretSift technical report

## 1. Problem
Regex and entropy secret scanners raise many false alerts (placeholders, hashes, UUIDs, test fixtures), so teams
learn to ignore them. A published comparison of open-source scanners found precision well below 50% for the best of them.
SecretSift keeps cheap candidate extraction but adds a context-aware classifier that decides whether a candidate is a
real secret, and ships a reproducible benchmark so scanners can be compared with numbers.

## 2. Pipeline
Candidates (provider patterns, secret-like assignments, high-entropy strings) -> 25 value/context features + TF-IDF of the
masked line -> classifier -> threshold -> finding with human-readable reasons. Outputs: text, JSON, SARIF, baselines, git history.

## 3. Data and leakage controls
- Negatives: real Python code from the installed site-packages (treated as clean). Hard decoys are planted: hashes, UUIDs,
  base64 blobs, placeholders, password hashes, ids.
- Positives: SYNTHETIC random values in real provider formats, planted into real files and synthetic config files.
- Files are assigned to train/val/test/bench by a hash of the path, so no file appears in two splits.
- Some formats are never used for training (SendGrid, npm, Shopify, Twilio, DigitalOcean) to test generalisation.
- A 30% "provider-dropout" augmentation stops the model relying on the prefix match alone.
- Threshold is chosen on the validation split only.

## 4. Models (three families, held-out files)
| Model | Val PR-AUC | Test F1 | Test precision | Test recall | F1 on unseen formats |
|---|---|---|---|---|---|
| logreg | 0.997 | 0.979 | 0.976 | 0.982 | 0.788 |
| hist_gbm (selected) | 0.999 | 0.993 | 0.991 | 0.994 | 0.722 |
| mlp | 0.998 | 0.982 | 0.985 | 0.979 | 0.722 |

## 5. Benchmark (483 planted secrets, 54645 lines of real code)
| Scanner | Precision | Recall | F1 | Recall on unseen formats | False alerts / 100k LOC (real code) | Decoys flagged |
|---|---|---|---|---|---|---|
| pattern-rules-only | 0.721 | 0.470 | 0.569 | 0.000 | 0.0 | 88 |
| rules+entropy (no ML) | 0.432 | 0.921 | 0.589 | 0.900 | 470.3 | 327 |
| SecretSift (ML filter) | 0.990 | 0.793 | 0.880 | 0.515 | 1.8 | 3 |
| detect-secrets (default) | 0.637 | 0.542 | 0.586 | 0.492 | 1.8 | 148 |

False alerts on real code are lines in real library code that a scanner flags (all treated as clean). Decoys flagged are planted placeholders, hashes and ids that were flagged.

## 6. Limitations (read this before trusting the numbers)
- Positives are synthetic and the decoys resemble the training decoys, so the benchmark is easier than real repositories.
  The real test is a labelled corpus of real leaks such as SecretBench; adding an adapter is the first roadmap item.
- Recall on formats never seen in training is clearly lower than on seen formats.
- Candidate extraction is Python-centric on real-code negatives; other languages are only covered by the synthetic config files.
- Baselines are `detect-secrets` with default settings and two ablations of SecretSift, not Gitleaks or TruffleHog.
- The tool finds possible secrets; it does not verify them against provider APIs. Rotate anything real.

## 7. Reproduce
`python manage.py all` (train, benchmark, tests, report). Results depend on the packages installed in your environment.

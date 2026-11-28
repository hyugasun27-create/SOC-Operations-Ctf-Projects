# TryHackMe — Supply Chain Attack Vectors
## AI/ML Model and Software Supply Chain Security Review

**Platform:** TryHackMe  
**Focus:** ML model artefact inspection, dependency security, version pinning, lockfiles, dependency confusion, vulnerability auditing, and SBOM generation  
**Role perspective:** Security Analyst / SOC L1 learning project  
**Environment:** Authorized TryHackMe lab VM  
**Status:** In progress — findings documented from completed steps; dependency audit step pending

> **Transparency:** This is a training-lab write-up based on commands run and output captured during the exercise. Only findings explicitly observed are recorded as confirmed.

## 1. Objectives

- Inspect a Keras model for potentially unsafe architecture components.
- Understand why Lambda layers require manual review.
- Review supply-chain controls for Python dependencies.
- Generate a CycloneDX SBOM with Syft.
- Learn how vulnerability scanning and SBOM inventory complement one another.

## 2. Model Architecture Inspection

Inspected the file:

`image_classifier_v2.h5`

The architecture inspection reported five layers:

| Layer type | Layer name | Assessment |
|---|---|---|
| InputLayer | `input_layer_1` | No warning |
| Flatten | `flatten_1` | No warning |
| Dense | `dense_2` | No warning |
| Dense | `dense_3` | No warning |
| Lambda | `manipulate_output` | **Requires manual review** |

The inspection script reported:

```text
[WARNING] Lambda  manipulate_output (function: manipulate_output)
RESULT: 1 layer(s) require review
Lambda (manipulate_output): Can contain arbitrary Python code that executes at inference time
```

**Finding:** The Lambda layer named `manipulate_output` is suspicious because Lambda layers may execute arbitrary Python code at inference time. This is a review flag—not proof that the layer is malicious. The layer's implementation and model provenance should be inspected before use.

## 3. Dependency Supply-Chain Controls

### Exact version pinning

Dependency declarations should use exact versions rather than unbounded package names. For example:

```text
# Avoid unbounded versions
numpy
requests

# Exact pins
numpy==1.24.3
requests==2.31.0
```

Exact pins reduce unexpected upgrades, but do not by themselves guarantee package integrity or eliminate known vulnerabilities.

### Hash-verified lockfiles

Lockfiles with package hashes can verify downloaded package contents against expected hashes. The lab discussed `pip-compile --generate-hashes` and Poetry lockfiles.

### Dependency vulnerability scanning

The intended audit command:

```bash
pip-audit -r /opt/supply-chain/project/requirements.txt
```

**Status:** The audit output has not yet been captured in this report. Vulnerable package counts and CVE details are therefore not asserted.

## 4. Private Package Index / Dependency Confusion

The lab discussed using a private package registry as the primary index for internal packages.

Example configuration shown in the room:

```ini
[global]
index-url = https://your-private-pypi.company.com/simple/
extra-index-url = https://pypi.org/simple/
```

This is a conceptual example only; it was not configured against a real private registry in the lab. Package-index configuration should be designed carefully, as using an extra index can still introduce package-resolution risks.

## 5. SBOM Generation with Syft

Generated a CycloneDX JSON SBOM for the sample project, excluding the virtual environment:

```bash
syft /opt/supply-chain/project/ --exclude './venv/**' -o cyclonedx-json > /tmp/sbom.json
```

Syft completed the local scan. The terminal displayed an online update-check timeout:

```text
ERROR failed to fetch latest version ... i/o timeout
✔ Indexed file system /opt/supply-chain/project
✔ Cataloged contents
├── Packages [6 packages]
├── File digests [1 files]
├── File metadata [1 locations]
└── Executables [0 executables]
WARN no explicit name and version provided for directory source
```

**Interpretation:** The network timeout occurred during Syft's latest-version check. The local catalogue completed, identifying six packages. The directory-source naming warning is informational and does not indicate that SBOM generation failed.

Output path:

`/tmp/sbom.json`

The inventory can also be displayed in table format:

```bash
syft /opt/supply-chain/project/ --exclude './venv/**' -o table
```

The generated JSON can be reviewed with:

```bash
cat /tmp/sbom.json | python3 -m json.tool | less
```

## 6. SBOM and ML Artefact Coverage

A conventional SBOM records software components and versions, including transitive dependencies. It supports impact analysis when a new vulnerability is disclosed.

ML projects also require additional artefact context that may not be represented in a standard software SBOM:

- Model provenance (source, creator, training framework)
- Dataset lineage and transformations
- Model-card documentation
- Model integrity and hashes
- Known limitations and evaluation metrics

## 7. Key Takeaways

- Model files are only one part of the ML attack surface; dependencies and build artefacts must also be assessed.
- A suspicious Lambda layer should be investigated, not automatically labelled malware.
- Pinning versions helps control dependency changes; hash verification adds integrity checks.
- Vulnerability scanners and SBOMs answer different questions: known vulnerabilities versus component inventory.
- A generated SBOM is useful for incident response, vulnerability impact analysis, and software governance.
- Keep evidence-based reporting: record scan output and avoid claiming vulnerabilities without the audit results.

## 8. Evidence / Completion Notes

| Activity | Status |
|---|---|
| Inspect `image_classifier_v2.h5` architecture | Completed |
| Identify suspicious Lambda layer | Completed — `manipulate_output` |
| Generate CycloneDX SBOM using Syft | Completed — six packages catalogued |
| Review Syft table output | Pending |
| Run `pip-audit` and document vulnerable packages | Pending |
| Review SBOM JSON | Pending |

## References

- [TryHackMe — Supply Chain Attack Vectors](https://tryhackme.com/jr/supplychain-attack-vectors)
- [Syft (Anchore)](https://github.com/anchore/syft)
- [pip-audit](https://github.com/pypa/pip-audit)
- [CycloneDX](https://cyclonedx.org/)

**Disclaimer:** Educational project in an authorized TryHackMe environment. No malicious model or package was executed as part of this documented work.

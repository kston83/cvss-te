# CVSS-VT: Vulnerability Threat Scoring System

Thank you to the original author of the tool [cvss-bt](https://github.com/t0sche/cvss-bt) 

## Overview

The Common Vulnerability Scoring System (CVSS) is an industry standard for assessing the severity of security vulnerabilities. While the National Vulnerability Database (NVD) provides CVSS Base scores, these alone are insufficient for effective vulnerability prioritization. 

This repository enhances vulnerability scoring through two complementary approaches:

1. **CVSS-BT (Base + Temporal)**: Enriches standard CVSS scores by incorporating the Exploit Code Maturity/Exploitability (E) Temporal Metric.
2. **CVSS-VT (Vulnerability Threat)**: An advanced scoring system that builds on CVSS-BT by incorporating exploit quality metrics and threat intelligence context.

## Data Sources

This repository continuously enriches and publishes vulnerability scores based on multiple threat intelligence sources:

- [CISA Known Exploited Vulnerabilities (KEV) Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [VulnCheck KEV](https://vulncheck.com/kev)
- [EPSS (Exploit Prediction Scoring System)](https://www.first.org/epss/)
- [Metasploit Framework](https://www.metasploit.com/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [Exploit DB](https://www.exploit-db.com/)
- [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub)

## CVSS-BT Scoring Logic

### Temporal Metric - Exploit Code Maturity/Exploitability (E)

The CVSS-BT score incorporates the Exploit Code Maturity/Exploitability (E) Temporal Metric based on available threat intelligence. This metric uses a prioritized decision tree to categorize vulnerabilities:

| Value | Description | Assigned When |
|-------|-------------|---------------|
| **Attacked (A)** (CVSS 4.0) | Vulnerability has verified attacks in the wild or widely available exploit solutions | • Found in CISA KEV or VulnCheck KEV<br>• EPSS score ≥ 0.36<br>• Has Metasploit module (for CVSS 4.0) |
| **High (H)** (CVSS 2.0/3.0/3.1) | Functional autonomous code exists with reliable exploitation | • Found in CISA KEV or VulnCheck KEV<br>• EPSS score ≥ 0.36<br>• High-quality Metasploit module (quality score ≥ 0.8) |
| **Functional (F)** (CVSS 2.0/3.0/3.1) | Functional exploit code is available that works in most situations | • Has Metasploit module (quality score < 0.8)<br>• Has Nuclei template<br>• Multiple high-quality PoCs (quality score ≥ 0.8 with multiple sources) |
| **Proof-of-Concept (P)** (CVSS 3.0/3.1/4.0) | Proof-of-concept exploit code is available but may not work in all situations | • Found in ExploitDB<br>• Has GitHub PoC |
| **Unproven (U)** (All CVSS versions) | No exploit code is available, or an exploit is theoretical | • Not present in any of the above threat intelligence sources |

The CVSS-BT score is calculated using the standard CVSS calculator with the updated vector string that includes the Exploit Code Maturity value.

### EPSS Threshold Explanation

The EPSS threshold of 0.36 (36%) is based on the F1 score of the EPSS v3 model. At approximately 37%, a CVE is highly likely to have weaponized exploit code available. This threshold is used as a signal for the "High" or "Attacked" exploit maturity designations.

## CVSS-VT Scoring Logic

The CVSS-VT score builds upon the CVSS-BT approach by incorporating additional dimensions:

1. **Base CVSS-BT Score**: Starting with the temporal score that already accounts for exploit maturity
2. **Exploit Quality Metrics**: Assessing the reliability, ease of use, and effectiveness of available exploits
3. **Threat Intelligence Context**: Incorporating additional threat landscape factors

### Exploit Quality Assessment

Each exploit source is evaluated based on three key metrics:

| Source | Reliability | Ease of Use | Effectiveness |
|--------|------------|-------------|---------------|
| Metasploit | 0.9 | 0.8 | 0.85 |
| ExploitDB | 0.7 | 0.6 | 0.7 |
| Nuclei | 0.8 | 0.9 | 0.75 |
| GitHub PoC | 0.5 | 0.4 | 0.6 |
| CISA KEV | 0.95 | 0.7 | 0.9 |
| VulnCheck KEV | 0.9 | 0.7 | 0.85 |

For Metasploit exploits, we further refine the reliability rating by incorporating the actual reliability and rank information from the module metadata when available.

The overall quality score is calculated as a weighted average:
- Reliability (40% weight)
- Ease of Use (30% weight)
- Effectiveness (30% weight)

### CVSS-VT Calculation

The CVSS-VT score is calculated using the following formula:

```
CVSS-VT = min(10, CVSS-BT_Score * Quality_Multiplier + Threat_Intel_Factor)
```

Where:

**Quality Multiplier**: Ranges from 0.8-1.2 based on exploit quality
- For poor quality exploits: closer to 0.8
- For high quality exploits: up to 1.2
- Formula: 0.8 + (quality_score * 0.4)

**Threat Intel Factor**: Adds 0-2 points based on additional threat intelligence
- CISA KEV or VulnCheck KEV presence: +1.0
- High EPSS score (≥ 0.5): +0.5
- Moderate EPSS score (≥ 0.36): +0.25
- Multiple exploit sources (≥ 3): +0.5
- Two exploit sources: +0.25

### CVSS-VT Severity Levels

| CVSS-VT Score | Severity Level |
|---------------|----------------|
| 9.0 - 10.0 | CRITICAL |
| 7.0 - 8.9 | HIGH |
| 4.0 - 6.9 | MEDIUM |
| 0.1 - 3.9 | LOW |
| 0.0 | NONE |

## Practical Application

Security professionals can utilize CVSS-VT scores to:

1. **Prioritize vulnerability remediation** based on actual threat context rather than just technical impact
2. **Allocate security resources** more effectively by focusing on vulnerabilities with higher threat potential
3. **Communicate risk** to stakeholders with more nuanced threat information
4. **Compare threat levels** across different types of vulnerabilities using a standardized approach

### Example Interpretation

A vulnerability with:
- CVSS Base Score: 7.5 (High)
- CVSS-BT Score: 6.5 (Adjusted based on exploit maturity)
- CVSS-VT Score: 8.3 (High)

This indicates that while the base severity is High, and temporal factors would typically reduce its practical severity, the additional threat intelligence suggests this is still a High-priority vulnerability due to factors like high-quality exploit availability, inclusion in KEV catalogs, or high EPSS prediction.

## Caveats and Considerations

- The CVSS-VT score is not an official CVSS metric and represents a custom approach to vulnerability prioritization
- The exploit quality metrics are based on empirical observations and security research but may not reflect all real-world scenarios
- While EPSS 0.36 is used as a threshold for exploit maturity calculation, we do not recommend using this percentage as a general threshold for prioritization
- CVSS-VT scores should be considered alongside other contextual factors such as asset criticality, data sensitivity, and compensating controls

## Acknowledgements

This product uses VulnCheck KEV and EPSS scores but is not endorsed or certified by the EPSS SIG or VulnCheck.

## Updates from Original CVSS-BT Implementation

This repository represents an evolution of the original CVSS-BT approach with the following enhancements:

1. Introduction of the CVSS-VT scoring system that extends beyond temporal metrics
2. More sophisticated exploit quality assessment based on multiple dimensions
3. Integration of additional threat intelligence context in score calculation
4. Enhanced vector string handling for CVSS 4.0 compatibility
5. More detailed explanation and transparency in score calculations
# CVSS-TE: Threat-Enhanced Vulnerability Scoring for Real-World Risk Assessment

## Executive Summary

This white paper introduces CVSS-TE (Common Vulnerability Scoring System - Threat Enhanced), a methodology that addresses critical limitations in traditional vulnerability scoring systems. While standard CVSS Base and Temporal scores provide valuable metrics for assessing vulnerability severity, they often fail to accurately represent real-world exploitation risk. The CVSS-TE approach incorporates sophisticated threat intelligence factors, exploit quality assessment, and time-based considerations to deliver more actionable vulnerability prioritization for security teams.

The CVSS-TE algorithm features: weighted quality metrics that emphasize high-quality exploits, calibrated assessments for unexploited vulnerabilities, intelligent handling of threat intelligence indicators, granular exploit source evaluation, and time-based decay factors. This methodology significantly improves the accuracy of vulnerability risk assessment and helps security teams focus on addressing the vulnerabilities that present the greatest actual threat to their environments.

## 1. Introduction

### 1.1 The Vulnerability Prioritization Challenge

Security teams today face an overwhelming number of vulnerabilities to address, with thousands of new CVEs published each year. The National Vulnerability Database (NVD) provides CVSS Base scores to indicate the inherent severity of vulnerabilities, but these scores alone are insufficient for effective prioritization in real-world scenarios. Many vulnerabilities with high CVSS Base scores never see active exploitation, while others with moderate scores become priority targets for attackers due to their accessibility and real-world weaponization.

### 1.2 Evolution of Vulnerability Scoring

The Common Vulnerability Scoring System (CVSS) has evolved through several versions (2.0, 3.0, 3.1, and most recently 4.0), gradually improving its ability to describe vulnerability characteristics. The CVSS Temporal metrics were introduced to account for factors that change over time, including exploit availability. However, even with Temporal adjustments, standard CVSS scoring lacks the nuance needed to differentiate between theoretical vulnerabilities and those actively being exploited in the wild.

The CVSS-TE (Threat Enhanced) methodology bridges this gap, incorporating threat intelligence and exploit metadata to provide a more accurate picture of real-world risk. This white paper details the CVSS-TE algorithm and its ability to identify and prioritize truly threatening vulnerabilities.

## 2. Threat Intelligence Sources and Integration

### 2.1 Data Source Overview

The CVSS-TE methodology integrates multiple threat intelligence sources to build a comprehensive view of each vulnerability's exploitation landscape:

- **CISA Known Exploited Vulnerabilities (KEV) Catalog**: Government-validated vulnerabilities with confirmed exploitation
- **VulnCheck KEV**: Commercial intelligence on exploited vulnerabilities
- **EPSS (Exploit Prediction Scoring System)**: Statistical probability of exploitation
- **Metasploit Framework**: Weaponized exploits with reliability and rank metadata
- **Nuclei Templates**: Detection scripts that indicate active scanning
- **Exploit DB**: Published proof-of-concept and public exploits
- **PoC-in-GitHub**: Community-developed proof-of-concept code

### 2.2 Quality Assessment Framework

Each exploit source is evaluated based on three key dimensions:

| Source | Reliability | Ease of Use | Effectiveness |
|--------|------------|-------------|---------------|
| Metasploit | 0.9 | 0.8 | 0.85 |
| ExploitDB | 0.7 | 0.6 | 0.7 |
| Nuclei | 0.8 | 0.9 | 0.75 |
| GitHub PoC | 0.5 | 0.4 | 0.6 |
| CISA KEV | 0.95 | 0.7 | 0.9 |
| VulnCheck KEV | 0.9 | 0.7 | 0.85 |

These metrics are weighted to calculate an overall quality score:
- Reliability (40% weight): How consistently the exploit works
- Ease of Use (30% weight): How much expertise is required to use the exploit
- Effectiveness (30% weight): How likely the exploit achieves its objective

## 3. CVSS-TE Methodology

The CVSS-TE algorithm incorporates several key approaches to better reflect real-world exploitation risk:

### 3.1 Exploit Quality Assessment

CVSS-TE employs a sophisticated weighted approach to evaluate exploit quality:
- 70% weight is given to the highest-quality exploit
- 30% weight is assigned to the average of remaining exploit sources

This prevents the dilution of high-quality exploits by lower-quality ones and better reflects the true exploitation risk. When a single high-quality exploit exists, it appropriately dominates the quality score.

### 3.2 Unexploited Vulnerability Evaluation

CVSS-TE applies nuanced handling of vulnerabilities with no observed exploitation evidence:
- If exploit_sources = 0 and EPSS < 0.36, the quality multiplier is set to 0.95
- This small reduction helps differentiate between unexploited vulnerabilities and those with at least some exploitation evidence

### 3.3 Intelligent Threat Intelligence Processing

CVSS-TE prevents excessive inflation from correlated threat indicators:
- When a vulnerability is confirmed as exploited (e.g., flagged in CISA KEV), the algorithm intelligently processes additional EPSS data
- Rather than summing both values, it uses the maximum of the KEV boost or the EPSS boost
- This avoids artificial inflation of scores based on correlated indicators

### 3.4 Granular Exploit Source Evaluation

CVSS-TE uses a graduated scale to evaluate the number of available exploit sources:
- 2 exploit sources: +0.25
- 3-4 exploit sources: +0.5
- 5 or more exploit sources: +0.75

This approach accurately reflects the real-world difference between vulnerabilities with limited versus widespread exploit availability.

### 3.5 Time-Based Risk Adjustment

CVSS-TE incorporates time as a factor in risk assessment:
- For vulnerabilities older than 5 years with no exploitation evidence, a time-based decay factor is applied
- The decay increases gradually with age, up to a maximum reduction of 0.2 points
- This adjustment reflects the diminishing risk of older, unexploited vulnerabilities

## 4. CVSS-TE Score Calculation

### 4.1 Algorithm Overview

The CVSS-TE score is calculated using the following formula:

```
CVSS-TE = min(10, (CVSS-BT_Score * Quality_Multiplier) + Threat_Intel_Factor - Time_Decay)
```

Where:

**Quality Multiplier**:
- For exploited vulnerabilities: 0.8 + (quality_score * 0.4), ranging from 0.8 to 1.2
- For unexploited vulnerabilities with EPSS < 0.36: 0.95
- For unexploited vulnerabilities with EPSS ≥ 0.36: 1.0

**Threat Intel Factor**: Sum of:
- KEV presence: +1.0 for CISA KEV or +0.8 for VulnCheck KEV
- EPSS score (if no KEV): +0.5 for EPSS ≥ 0.5 or +0.25 for EPSS ≥ 0.36
- Exploit sources: +0.25 for 2 sources, +0.5 for 3-4 sources, +0.75 for 5+ sources
- If both KEV and high EPSS are present, the maximum value is used

**Time Decay**:
- For vulnerabilities >5 years old with no exploits: min(0.2, (years_since_pub - 5) * 0.04)
- For other vulnerabilities: 0

### 4.2 CVSS-TE Severity Levels

The final CVSS-TE score maps to the following severity levels:

| CVSS-TE Score | Severity Level |
|---------------|----------------|
| 9.0 - 10.0 | CRITICAL |
| 7.0 - 8.9 | HIGH |
| 4.0 - 6.9 | MEDIUM |
| 0.1 - 3.9 | LOW |
| 0.0 | NONE |

## 5. Implementation and Analysis

### 5.1 Code Implementation

The core of the CVSS-TE algorithm is implemented through two key functions:

1. **Evaluate Exploit Quality**: Calculates the weighted quality metrics based on available exploit sources
2. **Calculate CVSS-TE Score**: Computes the final Threat-Enhanced score based on quality metrics, threat intelligence, and time factors

The implementation includes proper error handling to ensure robustness when processing diverse vulnerability data.

### 5.2 Impact Analysis

Analysis of CVSS-TE performance across thousands of CVEs reveals:

1. **Strong Differentiation**: CVSS-TE shows greater score differentiation between vulnerabilities with different exploitation profiles, avoiding the clustering sometimes seen in Base CVSS scores.

2. **Real-World Alignment**: Vulnerabilities that have caused significant real-world incidents consistently score higher in CVSS-TE than in standard CVSS.

3. **Reduced False Positives**: High-severity but unexploited vulnerabilities are appropriately categorized, reducing alert fatigue for security teams.

4. **Time Sensitivity**: The time decay factor appropriately adjusts the urgency of addressing older, unexploited vulnerabilities while maintaining focus on recent or actively exploited ones.

## 6. Case Studies

### 6.1 Case Study 1: Log4Shell (CVE-2021-44228)

This vulnerability scored 10.0 (Critical) in CVSS Base, 9.0 in CVSS-BT, and 10.0 in CVSS-TE due to:
- Multiple high-quality exploit sources (Metasploit, Nuclei, GitHub PoCs)
- Presence in CISA KEV and high EPSS score
- Widespread exploitation in the wild

CVSS-TE correctly identified this as a top-priority vulnerability requiring immediate attention.

### 6.2 Case Study 2: High-Severity but Unexploited Vulnerability

A vulnerability with CVSS Base score of 9.1 (Critical) but no exploitation evidence scored:
- 7.3 (High) in CVSS-BT due to the lack of exploit maturity
- 6.8 (Medium) in CVSS-TE due to the applied adjustment for unexploited vulnerabilities and low EPSS

This more accurate categorization helps security teams appropriately prioritize resources.

### 6.3 Case Study 3: Widely Exploited Moderate Vulnerability

A vulnerability with CVSS Base score of 7.5 (High) but significant real-world exploitation scored:
- 6.5 (Medium) in CVSS-BT
- 8.3 (High) in CVSS-TE due to multiple high-quality exploits and presence in KEV

CVSS-TE correctly elevated this vulnerability based on actual threat data, ensuring it receives appropriate attention despite its moderate base severity.

## 7. Operational Benefits

The CVSS-TE scoring system provides several key operational benefits for security teams:

### 7.1 Improved Resource Allocation

By accurately identifying truly critical vulnerabilities, security teams can allocate limited remediation resources more effectively. The algorithm helps distinguish between vulnerabilities that require immediate attention and those that can be addressed through regular patch cycles.

### 7.2 Reduced Alert Fatigue

The nuanced scoring approach reduces the number of false "Critical" alerts that traditional scoring might generate, focusing attention on vulnerabilities with genuine exploitation potential. This helps combat alert fatigue and prevents important vulnerabilities from being lost in the noise.

### 7.3 Better Alignment with Business Risk

CVSS-TE scores better reflect actual business risk by incorporating real-world exploitation data. This allows security teams to communicate more effectively with business stakeholders about the genuine risk posed by different vulnerabilities.

### 7.4 Enhanced Automation Support

The granular and well-calibrated CVSS-TE scores provide a more reliable foundation for automated vulnerability management workflows, allowing organizations to build more effective security automation without overcorrecting or underreacting to threats.

## 8. Limitations and Future Work

While the CVSS-TE methodology provides significant improvements over traditional vulnerability scoring, several limitations and areas for future enhancement remain:

### 8.1 Current Limitations

- **Dependency on Quality of Threat Intelligence**: The accuracy of CVSS-TE scores depends on the comprehensiveness and timeliness of the underlying threat intelligence data.
- **Industry-Specific Exploitation Patterns**: The current model doesn't account for industry-specific targeting patterns that might make certain vulnerabilities more critical for particular sectors.
- **Limited Historical Data for New Vulnerability Types**: Novel vulnerability classes may not have enough historical data for accurate exploitation prediction.

### 8.2 Future Research Directions

- **Industry-Specific Weighting**: Developing industry-specific CVSS-TE variants that adjust weightings based on observed attack patterns in different sectors.
- **Machine Learning Integration**: Incorporating machine learning to improve prediction of exploitation likelihood based on vulnerability characteristics.
- **Asset Exposure Context**: Integrating asset exposure information to provide context-aware scoring that considers the actual deployment environment.
- **Threat Actor TTPs Correlation**: Linking vulnerabilities to specific threat actor techniques, tactics, and procedures for more context-rich prioritization.

## 9. Conclusion

The CVSS-TE scoring methodology represents a significant advancement in vulnerability prioritization, bridging the gap between theoretical vulnerability severity and real-world exploitation risk. By incorporating refined exploit quality assessment, calibrated adjustments for unexploited vulnerabilities, intelligent processing of threat intelligence, granular source evaluation, and time-based factors, CVSS-TE provides security teams with a more accurate and actionable metric for vulnerability management.

Organizations implementing this approach can expect more effective resource allocation, reduced alert fatigue, and better alignment between security priorities and actual business risk. While opportunities for further refinement remain, CVSS-TE provides a solid foundation for risk-based vulnerability management in complex environments.

## References

1. FIRST.org. "Common Vulnerability Scoring System SIG." https://www.first.org/cvss/
2. CISA. "Known Exploited Vulnerabilities Catalog." https://www.cisa.gov/known-exploited-vulnerabilities-catalog
3. FIRST.org. "Exploit Prediction Scoring System (EPSS)." https://www.first.org/epss/
4. Allodi, L., & Massacci, F. (2014). "Comparing vulnerability severity and exploits using case-control studies." ACM Transactions on Information and System Security.
5. Jacobs, J., Romanosky, S., Adjerid, I., & Baker, W. (2019). "Improving vulnerability remediation through better exploit prediction." Workshop on the Economics of Information Security.
6. Spring, J., Householder, A., Jacobs, J., & Weaver, N. (2021). "Prioritizing vulnerability response: A stakeholder-specific vulnerability categorization." Workshop on the Economics of Information Security.
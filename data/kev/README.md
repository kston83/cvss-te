# CISA Known Exploited Vulnerabilities (KEV) Data

This directory contains the CISA KEV catalog used as a local fallback.

## 📥 Download Instructions

### Option 1: Direct Download (Recommended)
```bash
curl -o data/kev/known_exploited_vulnerabilities.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

Or using PowerShell:
```powershell
Invoke-WebRequest -Uri "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" -OutFile "data/kev/known_exploited_vulnerabilities.json"
```

### Option 2: Manual Download
1. Visit: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
2. Save the file as `known_exploited_vulnerabilities.json` in this directory

## 📊 File Details

- **Source:** [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Size:** ~200KB (compressed), ~2MB (uncompressed JSON)
- **Updates:** Daily by CISA
- **Current Count:** ~1450+ vulnerabilities

## 🔄 How It's Used

The dashboard uses a **dual-source strategy**:

1. **Remote First (Default):** Fetches from CISA's live feed on page load
   - Cached in browser localStorage for 24 hours
   - Always up-to-date

2. **Local Fallback:** Uses this file if remote fetch fails
   - Offline development
   - CISA site downtime
   - Network issues

## 🔧 Update Frequency

**For Development:**
- Update this file periodically (weekly/monthly)
- Or let it auto-fetch from remote (no local file needed)

**For Production:**
- Remote fetch is preferred (always current)
- Local file acts as safety net

## 📝 .gitignore

The JSON file is tracked in git by default. If you want to exclude it:

```gitignore
# Add to .gitignore if file is too large
data/kev/known_exploited_vulnerabilities.json
```

## 🧹 Maintenance

To update the local copy:
```bash
# Download latest from CISA
curl -o data/kev/known_exploited_vulnerabilities.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

# Or just delete it - remote fetch will work fine
rm data/kev/known_exploited_vulnerabilities.json
```

## ℹ️ File Format

The JSON structure:
```json
{
  "title": "CISA Catalog of Known Exploited Vulnerabilities",
  "catalogVersion": "2025.10.30",
  "dateReleased": "2025-10-30T17:58:16.1627Z",
  "count": 1453,
  "vulnerabilities": [
    {
      "cveID": "CVE-2025-41244",
      "vendorProject": "Broadcom",
      "product": "VMware Aria Operations",
      "vulnerabilityName": "...",
      "dateAdded": "2025-10-30",
      "shortDescription": "...",
      "requiredAction": "...",
      "dueDate": "2025-11-20",
      "knownRansomwareCampaignUse": "Unknown"
    }
  ]
}
```

## 🚀 Quick Start

**You don't need this file to start!** The dashboard works without it:
- First visit: Fetches from CISA (cached for 24h)
- Local file is optional fallback only


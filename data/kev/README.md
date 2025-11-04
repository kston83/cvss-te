# CISA KEV (Known Exploited Vulnerabilities) Data

## Overview

This directory contains the CISA Known Exploited Vulnerabilities catalog, which is automatically updated via GitHub Actions.

## How It Works

### Data Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    Browser (GitHub Pages)                        │
│                                                                   │
│  1. Check localStorage cache (24h expiry)                        │
│                    ↓ (if expired)                                │
│  2. Try CISA Direct: https://www.cisa.gov/.../feeds/*.json      │
│                    ↓ (fails due to CORS)                        │
│  3. Try Local Path: ./data/kev/*.json (GitHub Pages)            │
│                    ↓ (fallback)                                  │
│  4. Try GitHub Raw: https://raw.githubusercontent.com/...        │
│                                                                   │
│  → Cache result in localStorage for 24 hours                     │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     GitHub Actions (Server)                      │
│                                                                   │
│  Every 2 hours:                                                  │
│  1. Download from CISA directly (no CORS issues)                 │
│  2. Check if file changed                                        │
│  3. Commit & push to repo if different                           │
│  4. GitHub Pages automatically deploys update                    │
└─────────────────────────────────────────────────────────────────┘
```

### Why Three Fetch Attempts?

1. **CISA Direct** (`https://www.cisa.gov/...`)
   - **Always fails** in browsers due to CORS policy
   - Kept for potential future CORS support or server-side use
   - Fails fast, so minimal performance impact

2. **Relative Path** (`./data/kev/known_exploited_vulnerabilities.json`)
   - **Primary source** when running on GitHub Pages
   - Served directly from your deployed site
   - Fast, reliable, no external dependencies
   - **This is what actually works!**

3. **GitHub Raw** (`https://raw.githubusercontent.com/kston83/cvss-te/main/...`)
   - Final fallback if relative path fails
   - Works from any domain
   - Slightly slower due to external request

### Why Not Just Relative Path?

**We keep the full URL fallback because:**
- Testing locally (file:// protocol)
- Running on different domains
- CDN or mirror scenarios
- Redundancy is good!

## Files

- `known_exploited_vulnerabilities.json` - The actual KEV catalog (auto-updated)
- `download_kev.sh` - Manual download script (for local testing)
- `README.md` - This file

## GitHub Actions

### Automatic Updates (`.github/workflows/update-kev.yml`)

- **Frequency**: Every 2 hours
- **Source**: CISA official feed
- **Process**:
  1. Downloads latest KEV catalog
  2. Compares with existing file
  3. Commits only if changed
  4. Includes catalog version and count in commit message

### Manual Trigger

You can manually trigger an update:
```bash
gh workflow run update-kev.yml
```

Or via GitHub web interface: Actions → Update CISA KEV Catalog → Run workflow

## Local Testing

To download the KEV catalog manually:

```bash
bash data/kev/download_kev.sh
```

Or directly:
```bash
curl -L -o data/kev/known_exploited_vulnerabilities.json \
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
```

## Data Format

The KEV catalog contains:

```json
{
  "catalogVersion": "2024.11.04",
  "dateReleased": "2024-11-04T14:30:00.000Z",
  "count": 1234,
  "vulnerabilities": [
    {
      "cveID": "CVE-2024-XXXXX",
      "vendorProject": "Vendor Name",
      "product": "Product Name",
      "vulnerabilityName": "Description",
      "dateAdded": "2024-11-04",
      "shortDescription": "Detailed description...",
      "requiredAction": "Apply updates per vendor instructions.",
      "dueDate": "2024-11-25",
      "knownRansomwareCampaignUse": "Known",
      "notes": ""
    }
  ]
}
```

## Cache Strategy

The `kevEnricher.js` module implements a two-tier caching strategy:

1. **localStorage Cache** (24 hours)
   - Persists across page loads
   - Reduces network requests
   - Automatically expires after 24h

2. **In-Memory Cache**
   - Fast lookups via Map structure
   - Built once per session
   - CVE ID → KEV details mapping

## Integration with CVSS-TE

The KEV data enriches CVE records with:
- `cisa_kev_date_added` - When added to KEV catalog
- `kev_due_date` - CISA mandated patching deadline
- `kev_ransomware` - Known ransomware campaign use
- `kev_description` - CISA's description

This data is used to:
- Prioritize KEVs above all other vulnerabilities
- Display CISA deadlines prominently
- Flag ransomware-related threats
- Provide authoritative exploitation context

## Troubleshooting

### KEV data not loading on GitHub Pages

1. Check browser console for errors
2. Verify file exists at: `https://<username>.github.io/<repo>/data/kev/known_exploited_vulnerabilities.json`
3. Clear localStorage cache: Run in console:
   ```javascript
   localStorage.removeItem('cisa_kev_cache')
   ```
4. Check CSP allows the fetch (should include `connect-src 'self'`)

### GitHub Action not running

1. Verify workflow file is in `.github/workflows/`
2. Check Actions tab for errors
3. Ensure repo has Actions enabled (Settings → Actions → General)
4. Manual trigger via workflow_dispatch

### File not updating

1. Check if CISA catalog actually changed
2. Review GitHub Actions logs
3. Verify git commit permissions
4. Check file hasn't been modified manually (would cause merge conflict)

## References

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [CISA KEV JSON Feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- [GitHub Actions Cron Syntax](https://docs.github.com/en/actions/using-workflows/events-that-trigger-workflows#schedule)

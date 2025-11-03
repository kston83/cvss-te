# Security Policy

## Security Features

### 1. Content Security Policy (CSP)
The application implements a strict Content Security Policy to prevent XSS attacks:
- `default-src 'self'` - Only load resources from same origin
- `script-src` - Whitelist for scripts (self, Google Analytics, CDNs)
- `style-src` - Whitelist for styles (self, Tailwind CDN)
- `frame-ancestors 'none'` - Prevent clickjacking
- `base-uri 'self'` - Prevent base tag injection
- `form-action 'self'` - Restrict form submissions

### 2. Subresource Integrity (SRI)
External CDN resources use SRI hashes to ensure integrity:
- **PapaParse 5.3.2**: Full SRI hash validation
- **crossorigin="anonymous"**: CORS mode for CDN resources
- **referrerpolicy="no-referrer"**: Privacy protection

### 3. Security Headers
- **X-Content-Type-Options: nosniff** - Prevent MIME-sniffing
- **Referrer-Policy: strict-origin-when-cross-origin** - Control referrer information
- **Permissions-Policy** - Disable unnecessary browser features (geolocation, microphone, camera)

### 4. Input Validation
All user input is strictly validated:
- **CVE ID Parsing**: Regex validation `/^CVE-\d{4}-\d+$/`
- **Whitelist Approach**: Only valid CVE formats accepted
- **No Direct HTML Rendering**: User input never directly rendered in HTML

### 5. Data Source Security
- **CSV Data**: Loaded from trusted internal source
- **No User-Generated Content**: All displayed data from controlled CSV
- **Lazy Loading**: CSV loaded only when needed (reduces attack surface)

### 6. XSS Prevention
- **escapeHTML Utility**: Available for sanitizing untrusted content
- **textContent vs innerHTML**: Preference for safe DOM methods
- **Validated Input**: Strict regex validation prevents injection

## Security Audit Checklist

### ✅ Completed
- [x] Content Security Policy implemented
- [x] SRI hashes for CDN resources (PapaParse)
- [x] Security headers (X-Content-Type-Options, Referrer-Policy, Permissions-Policy)
- [x] Input validation (CVE ID regex)
- [x] crossorigin and referrerpolicy attributes on external resources
- [x] No hardcoded secrets in client code
- [x] HTTPS enforced (via GitHub Pages)
- [x] Privacy-focused analytics (anonymize_ip: true)

### 🛡️ Security Controls

| Control | Status | Implementation |
|---------|--------|----------------|
| XSS Prevention | ✅ | CSP, input validation, safe DOM methods |
| CSRF Protection | ✅ | No state-changing operations, CSP form-action |
| Clickjacking | ✅ | frame-ancestors 'none' |
| MIME Sniffing | ✅ | X-Content-Type-Options: nosniff |
| CDN Compromise | ✅ | SRI hash for PapaParse |
| Data Validation | ✅ | Regex validation for all inputs |
| Privacy | ✅ | anonymize_ip, strict referrer policy |

## Threat Model

### In Scope
- **XSS Attacks**: Prevented via CSP and input validation
- **CDN Compromise**: Mitigated via SRI (PapaParse)
- **Clickjacking**: Prevented via CSP frame-ancestors
- **MIME Confusion**: Prevented via X-Content-Type-Options

### Out of Scope
- Server-side vulnerabilities (static site on GitHub Pages)
- DDoS attacks (handled by GitHub infrastructure)
- Physical security

## Reporting Security Issues

If you discover a security vulnerability, please report it by:
1. **DO NOT** open a public GitHub issue
2. Email the maintainer with details
3. Allow reasonable time for patching before disclosure

## Security Best Practices for Deployment

1. **Use HTTPS Only**: Ensure site is served over HTTPS (GitHub Pages does this)
2. **Keep Dependencies Updated**: Regularly update PapaParse and other libraries
3. **Monitor CSP Violations**: Check browser console for CSP violation reports
4. **Review Analytics**: Ensure anonymize_ip remains enabled
5. **Audit Regularly**: Review security measures quarterly

## Known Limitations

1. **Tailwind CDN**: Cannot use SRI due to dynamic content (CDN updates automatically)
   - Mitigation: CSP whitelist, trusted CDN source
   - Consider: Self-hosting Tailwind for production if SRI required

2. **'unsafe-inline' in CSP**: Required for Tailwind and Google Analytics
   - Mitigation: Minimal inline scripts, all in trusted locations
   - Future: Consider moving to script files with nonces

## Compliance

- ✅ **OWASP Top 10 2021**: Primary vulnerabilities addressed
- ✅ **Privacy**: GDPR-friendly (no PII collection, IP anonymization)
- ✅ **Modern Browser Standards**: CSP Level 3, SRI support

## Version History

### v2.0 (Phase 4 - November 3, 2025)
- Implemented comprehensive CSP
- Added SRI for PapaParse
- Added security headers
- Documented security architecture

### v1.0 (Pre-refactor)
- Basic security measures
- No formal security documentation

---

**Last Updated**: November 3, 2025  
**Security Contact**: [Your contact info]


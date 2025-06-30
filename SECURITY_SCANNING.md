# Security Scanning Documentation

This repository implements automated security scanning using GitHub Actions to ensure the website and its dependencies remain secure.

## Overview

The security scanning system consists of multiple workflows that run different types of security checks:

1. **Comprehensive Security Scan** (`security-scan.yml`) - Full security audit
2. **OWASP ZAP Scan** (`zap-security-scan.yml`) - Web application security testing
3. **Trivy Vulnerability Scan** (`trivy-scan.yml`) - Dependency and secret scanning
4. **Lighthouse Security Audit** (via `lighthouserc.json`) - Performance and security best practices

## Security Workflows

### 1. Comprehensive Security Scan

**File**: `.github/workflows/security-scan.yml`

**Triggers**: Push to main, Pull requests, Weekly schedule (Mondays 2 AM)

This workflow performs:

- **Hugo site building** and local server setup
- **Trivy filesystem scan** for vulnerabilities
- **OWASP ZAP baseline scan** for web application security
- **SSL/TLS configuration check** (production only)
- **Security headers validation**
- **Lighthouse security audit**

### 2. OWASP ZAP Security Scan

**File**: `.github/workflows/zap-security-scan.yml`

**Triggers**: Push to main, Pull requests, Weekly schedule (Mondays 3 AM)

Focuses specifically on web application security testing:

- Builds and serves the Hugo site locally
- Runs OWASP ZAP baseline security scan
- Checks for common web vulnerabilities (OWASP Top 10)
- Generates detailed HTML security reports

### 3. Trivy Vulnerability Scan

**File**: `.github/workflows/trivy-scan.yml`

**Triggers**: Push to main, Pull requests, Weekly schedule (Mondays 4 AM)

Comprehensive dependency and repository scanning:

- Scans for known vulnerabilities in dependencies
- Searches for exposed secrets and credentials
- Checks configuration files for security issues
- Uploads results to GitHub Security tab (SARIF format)

## Configuration Files

### ZAP Scanning Rules

**File**: `.zap/rules.tsv`

Configures OWASP ZAP scanning behavior:

- Sets warning levels for different security checks
- Ignores false positives common to static sites
- Focuses on relevant security issues for Hugo websites

Key rules configured:

- **WARN**: Missing security headers (CSP, X-Frame-Options, etc.)
- **IGNORE**: Static site specific false positives
- **WARN**: XSS protection and transport security

### Lighthouse Configuration

**File**: `lighthouserc.json`

Enhanced with security-focused audits:

- Performance and accessibility checks
- Security best practices validation
- HTTPS enforcement
- External link security (`rel="noopener"`)
- Vulnerable library detection

## Security Checks Performed

### Web Application Security (OWASP ZAP)

- Cross-Site Scripting (XSS) vulnerabilities
- SQL Injection attempts
- Security header presence and configuration
- Cookie security settings
- SSL/TLS configuration
- Authentication and session management

### Dependency Security (Trivy)

- Known vulnerabilities in npm packages
- Outdated dependencies with security issues
- License compliance issues
- Container image vulnerabilities (if applicable)

### Secret Scanning (Trivy)

- API keys and tokens
- Database credentials
- SSH keys and certificates
- Cloud service credentials
- Generic secrets patterns

### Configuration Security

- HTTP security headers
- SSL/TLS configuration
- Content Security Policy (CSP)
- Cross-Origin Resource Sharing (CORS)

## Interpreting Results

### GitHub Security Tab

- Navigate to **Security > Code scanning alerts**
- Review Trivy findings with severity levels
- Click on alerts for detailed remediation guidance

### Workflow Artifacts

Each workflow uploads detailed reports:

- **ZAP Security Report**: `zap-security-report` artifact
- **Trivy Vulnerability Report**: `trivy-vulnerability-report` artifact
- **Trivy Secrets Report**: `trivy-secrets-report` artifact
- **SSL Configuration**: `ssl-report` artifact
- **Security Headers**: `security-headers` artifact

### Lighthouse Reports

- Temporary public storage links in workflow output
- Performance, accessibility, and security scores
- Specific recommendations for improvements

## Responding to Security Issues

### Critical and High Severity

1. **Immediate action required**
2. Review the specific vulnerability details
3. Update affected dependencies
4. Test the fix in a pull request
5. Deploy the fix promptly

### Medium Severity

1. **Plan remediation within 30 days**
2. Evaluate impact and exploitability
3. Schedule dependency updates
4. Consider workarounds if updates unavailable

### Low Severity and Informational

1. **Address during regular maintenance**
2. Include in routine dependency updates
3. Document any accepted risks

## Customizing Security Scans

### Adding New URLs to Scan

Edit the workflow files to include additional pages:

```yaml
- name: ZAP Baseline Scan
  with:
    target: 'http://localhost:8080/new-page'
```

### Modifying ZAP Rules

Edit `.zap/rules.tsv` to adjust scanning behavior:

```tsv
rule_id  WARN|FAIL|INFO|IGNORE  parameter
10021    FAIL                   # Make missing headers a failure
```

### Lighthouse Security Audits

Add new security assertions in `lighthouserc.json`:

```json
"assertions": {
  "no-vulnerable-libraries": "error",
  "external-anchors-use-rel-noopener": "error"
}
```

## Scheduled Scans

All security workflows run weekly on Mondays:

- **2 AM**: Comprehensive security scan
- **3 AM**: OWASP ZAP focused scan  
- **4 AM**: Trivy vulnerability scan

This staggered schedule prevents resource conflicts and provides comprehensive coverage throughout the week.

## Security Best Practices

### For Static Sites

1. **Regular dependency updates** via Dependabot
2. **Security header implementation** via server configuration
3. **Content Security Policy** to prevent XSS
4. **Subresource Integrity** for external scripts
5. **HTTPS enforcement** for all content

### For CI/CD Security

1. **Secrets management** using GitHub Secrets
2. **Workflow permissions** following least privilege
3. **Artifact encryption** for sensitive reports
4. **Branch protection** requiring security scan passage

## Troubleshooting

### Common Issues

#### ZAP Scan Timeouts

- Increase sleep time before scan starts
- Check local server startup logs
- Verify site builds successfully

#### Trivy False Positives

- Review vulnerability details carefully
- Consider adding ignores for confirmed false positives
- Update Trivy database regularly

#### SSL Labs API Limits

- Scans run only on main branch pushes
- Weekly scheduled scans respect rate limits
- Consider caching results for development

### Getting Help

1. Check workflow logs for specific error messages
2. Review security tool documentation:
   - [OWASP ZAP](https://www.zaproxy.org/docs/)
   - [Trivy](https://aquasecurity.github.io/trivy/)
   - [Lighthouse](https://web.dev/lighthouse-ci/)
3. Open an issue for persistent problems

This comprehensive security scanning setup ensures your Hugo website maintains high security standards while providing detailed visibility into potential vulnerabilities and misconfigurations.

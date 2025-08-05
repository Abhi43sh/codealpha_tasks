#!/usr/bin/env python3
"""
Secure Code Review Tool
A comprehensive security audit tool that performs static analysis to identify
security vulnerabilities and provides remediation recommendations.

Supports multiple programming languages: Python, JavaScript, Java, C/C++, PHP
"""

import os
import re
import json
import argparse
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from enum import Enum

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Vulnerability:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    recommendation: str
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None

class SecureCodeReviewer:
    def __init__(self):
        self.vulnerabilities: List[Vulnerability] = []
        self.supported_extensions = {
            '.py': 'python',
            '.js': 'javascript', 
            '.ts': 'typescript',
            '.java': 'java',
            '.c': 'c',
            '.cpp': 'cpp',
            '.cc': 'cpp',
            '.cxx': 'cpp',
            '.php': 'php',
            '.go': 'go',
            '.rb': 'ruby',
            '.cs': 'csharp'
        }
        
        
        self.security_rules = self._load_security_rules()
    
    def _load_security_rules(self) -> Dict:
        """Load security rules for different programming languages"""
        return {
            'python': {
                'sql_injection': [
                    (r'cursor\.execute\s*\(\s*["\'].*%.*["\']', 'String formatting in SQL query'),
                    (r'cursor\.execute\s*\(\s*.*\+.*\)', 'String concatenation in SQL query'),
                    (r'\.format\s*\(.*\).*execute', 'String format in SQL execution')
                ],
                'command_injection': [
                    (r'os\.system\s*\(\s*.*\+', 'Command injection via os.system'),
                    (r'subprocess\.call\s*\(\s*.*\+', 'Command injection via subprocess'),
                    (r'eval\s*\(', 'Dangerous use of eval()'),
                    (r'exec\s*\(', 'Dangerous use of exec()')
                ],
                'xss': [
                    (r'render_template_string\s*\(.*\+', 'XSS via template string injection'),
                    (r'Markup\s*\(.*\+', 'XSS via unsafe Markup usage')
                ],
                'insecure_random': [
                    (r'random\.random\(\)', 'Cryptographically weak random number'),
                    (r'random\.randint\(', 'Cryptographically weak random number')
                ],
                'hardcoded_secrets': [
                    (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded password'),
                    (r'api_key\s*=\s*["\'][^"\']{16,}["\']', 'Hardcoded API key'),
                    (r'secret\s*=\s*["\'][^"\']{16,}["\']', 'Hardcoded secret')
                ],
                'path_traversal': [
                    (r'open\s*\(\s*.*\+.*\)', 'Potential path traversal in file operations'),
                    (r'os\.path\.join\s*\(.*request\.|os\.path\.join\s*\(.*input\(', 'Path traversal risk')
                ],
                'deserialization': [
                    (r'pickle\.loads?\s*\(', 'Unsafe deserialization with pickle'),
                    (r'yaml\.load\s*\(', 'Unsafe YAML deserialization')
                ]
            },
            'javascript': {
                'xss': [
                    (r'innerHTML\s*=\s*.*\+', 'XSS via innerHTML manipulation'),
                    (r'document\.write\s*\(.*\+', 'XSS via document.write'),
                    (r'eval\s*\(', 'Dangerous use of eval()')
                ],
                'sql_injection': [
                    (r'query\s*\(\s*["\'].*\+.*["\']', 'SQL injection via string concatenation'),
                    (r'execute\s*\(\s*.*\+', 'SQL injection in query execution')
                ],
                'command_injection': [
                    (r'exec\s*\(\s*.*\+', 'Command injection via exec'),
                    (r'child_process\.exec\s*\(.*\+', 'Command injection via child_process')
                ],
                'insecure_random': [
                    (r'Math\.random\(\)', 'Cryptographically weak random number')
                ],
                'prototype_pollution': [
                    (r'__proto__', 'Potential prototype pollution'),
                    (r'constructor\.prototype', 'Prototype manipulation risk')
                ]
            },
            'java': {
                'sql_injection': [
                    (r'Statement\.execute\s*\(\s*.*\+', 'SQL injection via string concatenation'),
                    (r'createStatement\(\)\.execute\(.*\+', 'SQL injection in statement execution')
                ],
                'command_injection': [
                    (r'Runtime\.getRuntime\(\)\.exec\s*\(.*\+', 'Command injection via Runtime.exec'),
                    (r'ProcessBuilder\s*\(.*\+', 'Command injection via ProcessBuilder')
                ],
                'path_traversal': [
                    (r'new File\s*\(.*\+', 'Path traversal in File constructor'),
                    (r'Files\.newInputStream\s*\(.*\+', 'Path traversal in file operations')
                ],
                'deserialization': [
                    (r'ObjectInputStream\.readObject\(\)', 'Unsafe deserialization'),
                    (r'XMLDecoder\.readObject\(\)', 'Unsafe XML deserialization')
                ]
            },
            'php': {
                'sql_injection': [
                    (r'mysql_query\s*\(\s*.*\$', 'SQL injection via mysql_query'),
                    (r'mysqli_query\s*\(.*\$', 'SQL injection via mysqli_query'),
                    (r'\$.*->query\s*\(.*\$', 'SQL injection via query method')
                ],
                'command_injection': [
                    (r'system\s*\(.*\$', 'Command injection via system()'),
                    (r'exec\s*\(.*\$', 'Command injection via exec()'),
                    (r'shell_exec\s*\(.*\$', 'Command injection via shell_exec()')
                ],
                'file_inclusion': [
                    (r'include\s*\(.*\$', 'Local/Remote file inclusion'),
                    (r'require\s*\(.*\$', 'Local/Remote file inclusion'),
                    (r'include_once\s*\(.*\$', 'Local/Remote file inclusion')
                ],
                'xss': [
                    (r'echo\s+.*\$', 'Potential XSS via echo'),
                    (r'print\s+.*\$', 'Potential XSS via print')
                ]
            }
        }
    
    def scan_directory(self, directory_path: str, exclude_dirs: List[str] = None) -> None:
        """Scan a directory for security vulnerabilities"""
        if exclude_dirs is None:
            exclude_dirs = ['.git', '__pycache__', 'node_modules', '.venv', 'venv']
        
        directory = Path(directory_path)
        
        for file_path in directory.rglob('*'):
        
            if file_path.is_dir():
                continue
            
            if any(excl in str(file_path) for excl in exclude_dirs):
                continue
            
            if file_path.suffix.lower() in self.supported_extensions:
                self.scan_file(str(file_path))
    
    def scan_file(self, file_path: str) -> None:
        """Scan a single file for security vulnerabilities"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
                lines = content.split('\n')
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
            return
        
        file_ext = Path(file_path).suffix.lower()
        language = self.supported_extensions.get(file_ext, 'unknown')
        
        if language in self.security_rules:
            self._analyze_code(file_path, lines, language)
    
    def _analyze_code(self, file_path: str, lines: List[str], language: str) -> None:
        """Analyze code for security vulnerabilities"""
        rules = self.security_rules[language]
        
        for line_num, line in enumerate(lines, 1):
            line_stripped = line.strip()
            
            
            if not line_stripped or self._is_comment(line_stripped, language):
                continue
            
            # Check each security rule category
            for category, patterns in rules.items():
                for pattern, description in patterns:
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerability = self._create_vulnerability(
                            category, description, file_path, line_num, 
                            line_stripped, language
                        )
                        self.vulnerabilities.append(vulnerability)
    
    def _is_comment(self, line: str, language: str) -> bool:
        """Check if line is a comment"""
        comment_patterns = {
            'python': r'^\s*#',
            'javascript': r'^\s*(//|/\*)',
            'typescript': r'^\s*(//|/\*)',
            'java': r'^\s*(//|/\*)',
            'c': r'^\s*(//|/\*)',
            'cpp': r'^\s*(//|/\*)',
            'php': r'^\s*(//|#|/\*)',
            'go': r'^\s*//',
            'ruby': r'^\s*#',
            'csharp': r'^\s*(//|/\*)'
        }
        
        pattern = comment_patterns.get(language, r'^\s*#')
        return bool(re.match(pattern, line))
    
    def _create_vulnerability(self, category: str, description: str, file_path: str, 
                            line_num: int, code_snippet: str, language: str) -> Vulnerability:
        """Create a vulnerability object with recommendations"""
        
        severity_mapping = {
            'sql_injection': (Severity.CRITICAL, 'A1:2017-Injection'),
            'command_injection': (Severity.CRITICAL, 'A1:2017-Injection'),
            'xss': (Severity.HIGH, 'A7:2017-Cross-Site Scripting (XSS)'),
            'deserialization': (Severity.HIGH, 'A8:2017-Insecure Deserialization'),
            'path_traversal': (Severity.HIGH, 'A5:2017-Broken Access Control'),
            'file_inclusion': (Severity.HIGH, 'A5:2017-Broken Access Control'),
            'hardcoded_secrets': (Severity.MEDIUM, 'A2:2017-Broken Authentication'),
            'insecure_random': (Severity.MEDIUM, 'A6:2017-Security Misconfiguration'),
            'prototype_pollution': (Severity.MEDIUM, 'A6:2017-Security Misconfiguration')
        }
        
        severity, owasp = severity_mapping.get(category, (Severity.LOW, None))
        
        recommendations = self._get_recommendations(category, language)
        
        vuln_id = hashlib.md5(f"{file_path}:{line_num}:{category}".encode()).hexdigest()[:8]
        
        return Vulnerability(
            id=vuln_id,
            title=f"{category.replace('_', ' ').title()} Vulnerability",
            severity=severity,
            category=category,
            description=description,
            file_path=file_path,
            line_number=line_num,
            code_snippet=code_snippet,
            recommendation=recommendations,
            owasp_category=owasp
        )
    
    def _get_recommendations(self, category: str, language: str) -> str:
        """Get remediation recommendations for vulnerability categories"""
        recommendations = {
            'sql_injection': {
                'python': "Use parameterized queries with cursor.execute(query, (param1, param2)). Consider using SQLAlchemy ORM with bound parameters.",
                'javascript': "Use parameterized queries or prepared statements. For Node.js, use libraries like 'mysql2' with parameter binding.",
                'java': "Use PreparedStatement with parameter binding: PreparedStatement ps = conn.prepareStatement('SELECT * FROM users WHERE id = ?'); ps.setInt(1, userId);",
                'php': "Use prepared statements with PDO: $stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?'); $stmt->execute([$userId]);"
            },
            'command_injection': {
                'python': "Avoid os.system() and shell=True. Use subprocess with a list of arguments: subprocess.run(['command', 'arg1', 'arg2']). Validate and sanitize all inputs.",
                'javascript': "Use child_process.execFile() or spawn() with argument arrays instead of exec(). Validate and sanitize all user inputs.",
                'java': "Use ProcessBuilder with individual arguments instead of Runtime.exec() with shell commands. Validate all user inputs.",
                'php': "Avoid system(), exec(), shell_exec(). Use escapeshellarg() and escapeshellcmd() for input sanitization, or better yet, use specific libraries."
            },
            'xss': {
                'python': "Use template engines with auto-escaping (like Jinja2). For Flask, use escape() function or |safe filter carefully. Validate and sanitize all user inputs.",
                'javascript': "Use textContent instead of innerHTML. Implement Content Security Policy (CSP). Validate and escape all user inputs before rendering.",
                'php': "Use htmlspecialchars() or htmlentities() to escape output. Implement Content Security Policy (CSP) headers."
            },
            'deserialization': {
                'python': "Avoid pickle.loads() with untrusted data. Use JSON or implement custom serialization with validation. Consider using safer alternatives like msgpack.",
                'java': "Implement input validation and use whitelisting for allowed classes. Consider using JSON instead of Java serialization for untrusted data."
            },
            'path_traversal': {
                'python': "Use os.path.abspath() and os.path.commonprefix() to validate paths. Implement path sanitization and use os.path.join() carefully.",
                'java': "Use Path.normalize() and validate against allowed directories. Implement proper input validation and canonical path checking."
            },
            'hardcoded_secrets': {
                'python': "Use environment variables or secure configuration files. Consider using libraries like python-dotenv for development and proper secret management in production.",
                'javascript': "Use environment variables (process.env) or configuration files not committed to version control. Use tools like dotenv for development.",
                'java': "Use properties files, environment variables, or secure vault solutions. Never commit secrets to version control.",
                'php': "Use $_ENV variables or configuration files outside the web root. Consider using tools like Vault for secret management."
            },
            'insecure_random': {
                'python': "Use secrets module for cryptographic purposes: secrets.randbelow(), secrets.token_hex(), etc.",
                'javascript': "Use crypto.randomBytes() or crypto.getRandomValues() for cryptographic random numbers.",
                'java': "Use SecureRandom class instead of Random for cryptographic purposes."
            }
        }
        
        default_rec = "Review this code for potential security issues. Implement proper input validation, output encoding, and follow secure coding practices."
        
        return recommendations.get(category, {}).get(language, default_rec)
    
    def generate_report(self, output_format: str = 'json', output_file: str = None) -> str:
        """Generate security report in various formats"""
        if output_format.lower() == 'json':
            return self._generate_json_report(output_file)
        elif output_format.lower() == 'html':
            return self._generate_html_report(output_file)
        elif output_format.lower() == 'markdown':
            return self._generate_markdown_report(output_file)
        else:
            return self._generate_text_report(output_file)
    
    def _generate_json_report(self, output_file: str = None) -> str:
        """Generate JSON report"""
        report_data = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'total_vulnerabilities': len(self.vulnerabilities),
                'severity_breakdown': self._get_severity_breakdown()
            },
            'vulnerabilities': [asdict(vuln) for vuln in self.vulnerabilities]
        }
        
        json_report = json.dumps(report_data, indent=2, default=str)
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(json_report)
        
        return json_report
    
    def _generate_html_report(self, output_file: str = None) -> str:
        """Generate HTML report"""
        severity_breakdown = self._get_severity_breakdown()
        
        html_report = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Security Code Review Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .header {{ background-color: #2c3e50; color: white; padding: 20px; border-radius: 5px; }}
        .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; border-radius: 5px; }}
        .vulnerability {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #e74c3c; }}
        .high {{ border-left: 5px solid #f39c12; }}
        .medium {{ border-left: 5px solid #f1c40f; }}
        .low {{ border-left: 5px solid #27ae60; }}
        .code {{ background-color: #f8f9fa; padding: 10px; border-radius: 3px; font-family: monospace; }}
        .recommendation {{ background-color: #d5f4e6; padding: 10px; border-radius: 3px; margin-top: 10px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Security Code Review Report</h1>
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <div class="summary">
        <h2>📊 Summary</h2>
        <p><strong>Total Vulnerabilities Found:</strong> {len(self.vulnerabilities)}</p>
        <ul>
            <li>🔴 Critical: {severity_breakdown.get('CRITICAL', 0)}</li>
            <li>🟠 High: {severity_breakdown.get('HIGH', 0)}</li>
            <li>🟡 Medium: {severity_breakdown.get('MEDIUM', 0)}</li>
            <li>🟢 Low: {severity_breakdown.get('LOW', 0)}</li>
        </ul>
    </div>
    
    <h2>🔍 Detailed Findings</h2>
"""
        
        for vuln in sorted(self.vulnerabilities, key=lambda x: x.severity.value):
            severity_class = vuln.severity.value.lower()
            html_report += f"""
    <div class="vulnerability {severity_class}">
        <h3>🚨 {vuln.title}</h3>
        <p><strong>Severity:</strong> {vuln.severity.value}</p>
        <p><strong>Category:</strong> {vuln.category}</p>
        <p><strong>File:</strong> {vuln.file_path}:{vuln.line_number}</p>
        <p><strong>Description:</strong> {vuln.description}</p>
        
        <h4>📝 Code Snippet:</h4>
        <div class="code">{vuln.code_snippet}</div>
        
        <h4>💡 Recommendation:</h4>
        <div class="recommendation">{vuln.recommendation}</div>
        
        {f'<p><strong>OWASP Category:</strong> {vuln.owasp_category}</p>' if vuln.owasp_category else ''}
    </div>
"""
        
        html_report += """
</body>
</html>
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(html_report)
        
        return html_report
    
    def _generate_markdown_report(self, output_file: str = None) -> str:
        """Generate Markdown report"""
        severity_breakdown = self._get_severity_breakdown()
        
        md_report = f"""# 🔒 Security Code Review Report

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## 📊 Executive Summary

- **Total Vulnerabilities Found:** {len(self.vulnerabilities)}
- 🔴 **Critical:** {severity_breakdown.get('CRITICAL', 0)}
- 🟠 **High:** {severity_breakdown.get('HIGH', 0)}
- 🟡 **Medium:** {severity_breakdown.get('MEDIUM', 0)}
- 🟢 **Low:** {severity_breakdown.get('LOW', 0)}

## 🔍 Detailed Findings

"""
        
        for i, vuln in enumerate(sorted(self.vulnerabilities, key=lambda x: x.severity.value), 1):
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠', 
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(vuln.severity.value, '⚪')
            
            md_report += f"""### {i}. {severity_emoji} {vuln.title}

- **Severity:** {vuln.severity.value}
- **Category:** {vuln.category}
- **File:** `{vuln.file_path}:{vuln.line_number}`
- **Description:** {vuln.description}

**Code Snippet:**
```
{vuln.code_snippet}
```

**💡 Recommendation:** {vuln.recommendation}

{f'**OWASP Category:** {vuln.owasp_category}' if vuln.owasp_category else ''}

---

"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(md_report)
        
        return md_report
    
    def _generate_text_report(self, output_file: str = None) -> str:
        """Generate plain text report"""
        severity_breakdown = self._get_severity_breakdown()
        
        text_report = f"""
{'='*60}
         SECURITY CODE REVIEW REPORT
{'='*60}

Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

SUMMARY:
--------
Total Vulnerabilities: {len(self.vulnerabilities)}
Critical: {severity_breakdown.get('CRITICAL', 0)}
High: {severity_breakdown.get('HIGH', 0)}
Medium: {severity_breakdown.get('MEDIUM', 0)}
Low: {severity_breakdown.get('LOW', 0)}

DETAILED FINDINGS:
------------------
"""
        
        for i, vuln in enumerate(sorted(self.vulnerabilities, key=lambda x: x.severity.value), 1):
            text_report += f"""
[{i}] {vuln.title}
Severity: {vuln.severity.value}
Category: {vuln.category}
File: {vuln.file_path}:{vuln.line_number}
Description: {vuln.description}

Code Snippet:
{vuln.code_snippet}

Recommendation:
{vuln.recommendation}

{f'OWASP Category: {vuln.owasp_category}' if vuln.owasp_category else ''}

{'-'*60}
"""
        
        if output_file:
            with open(output_file, 'w') as f:
                f.write(text_report)
        
        return text_report
    
    def _get_severity_breakdown(self) -> Dict[str, int]:
        """Get count of vulnerabilities by severity"""
        breakdown = {}
        for vuln in self.vulnerabilities:
            severity = vuln.severity.value
            breakdown[severity] = breakdown.get(severity, 0) + 1
        return breakdown
    
    def print_summary(self) -> None:
        """Print a summary of findings"""
        severity_breakdown = self._get_severity_breakdown()
        
        print("\n" + "="*60)
        print("         SECURITY SCAN SUMMARY")
        print("="*60)
        print(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        print("\nSeverity breakdown:")
        print(f"  🔴 Critical: {severity_breakdown.get('CRITICAL', 0)}")
        print(f"  🟠 High:     {severity_breakdown.get('HIGH', 0)}")
        print(f"  🟡 Medium:   {severity_breakdown.get('MEDIUM', 0)}")
        print(f"  🟢 Low:      {severity_breakdown.get('LOW', 0)}")
        
        if self.vulnerabilities:
            print(f"\n⚠️  Priority: Address {severity_breakdown.get('CRITICAL', 0)} critical and {severity_breakdown.get('HIGH', 0)} high severity issues first!")


def main():
    parser = argparse.ArgumentParser(description='Secure Code Review Tool')
    parser.add_argument('path', nargs='?', default='.', 
                       help='File or directory path to scan (default: current directory)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-f', '--format', choices=['json', 'html', 'markdown', 'text'], 
                       default='text', help='Report format')
    parser.add_argument('--exclude', nargs='*', default=[], 
                       help='Directories to exclude from scan')
    parser.add_argument('--summary-only', action='store_true', 
                       help='Show only summary without detailed report')
    
    args = parser.parse_args()
    
    
    scanner = SecureCodeReviewer()
    
    print("🔒 Starting Security Code Review...")
    print(f"📁 Scanning: {args.path}")
    
    
    if os.path.isfile(args.path):
        scanner.scan_file(args.path)
    elif os.path.isdir(args.path):
        scanner.scan_directory(args.path, args.exclude)
    else:
        print(f"❌ Error: Path '{args.path}' does not exist!")
        return
    
    
    scanner.print_summary()
    
    if not args.summary_only:
        
        report = scanner.generate_report(args.format, args.output)
        
        if args.output:
            print(f"\n📄 Detailed report saved to: {args.output}")
        else:
            print(f"\n📄 Detailed Report ({args.format.upper()}):")
            print("="*60)
            if args.format != 'html':  # Don't print HTML to console
                print(report)


if __name__ == "__main__":
    main()

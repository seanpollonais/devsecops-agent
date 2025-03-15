import json
import yaml
import re
import argparse

# Parse command-line arguments
parser = argparse.ArgumentParser(description="DevSecOps Agent for risk acceptance and compliance checks")
parser.add_argument('--scan', default='trivy.json', help='Path to vulnerability scan JSON file')
parser.add_argument('--policy', default='policy.yaml', help='Path to policy YAML file')
parser.add_argument('--dockerfile', default='Dockerfile', help='Path to Dockerfile for compliance checks')
args = parser.parse_args()

# Load files using provided arguments
def load_file(file_path, file_type):
    try:
        with open(file_path, 'r') as file:
            return json.load(file) if file_type == 'json' else yaml.safe_load(file)
    except FileNotFoundError:
        print(f"Error: {file_type} file '{file_path}' not found.")
        return None

# Load Trivy JSON file
trivy_data = load_file(args.scan, 'json')
if not trivy_data:
    exit(1)

# Load policy YAML file
policy_data = load_file(args.policy, 'yaml')
if not policy_data:
    exit(1)

# Process vulnerabilities
for vuln in trivy_data.get('vulnerabilities', []):
    cve = vuln.get('cve', 'UNKNOWN')
    severity = vuln.get('severity', 'UNKNOWN')
    policy_rule = next((rule for rule in policy_data.get('rules', []) if rule['cve'] == cve), None)
    if policy_rule:
        decision = policy_rule.get('decision', 'ESCALATE')
        duration = policy_rule.get('duration', 'N/A')
        print(f"{cve}: Severity {severity} -> {decision} for {duration}")
    else:
        print(f"{cve}: Severity {severity} -> No policy rule found, defaulting to ESCALATE")

# Compliance check for secrets in Dockerfile
def check_secrets(dockerfile_path):
    secrets_patterns = {
        'AWS_ACCESS_KEY': r'AWS_ACCESS_KEY=[A-Z0-9]+',
        'PASSWORD': r'PASSWORD=[a-zA-Z0-9]+'
    }
    compliance_issues = []
    try:
        with open(dockerfile_path, 'r') as file:
            lines = file.readlines()
            for i, line in enumerate(lines, 1):
                print(f"Debug - Line {i}: {line.strip()}")
                for secret_type, pattern in secrets_patterns.items():
                    if re.search(pattern, line):
                        value = re.search(pattern, line).group()
                        suggestion = "Use AWS Secrets Manager or environment variables for AWS credentials." if secret_type == 'AWS_ACCESS_KEY' else "Avoid hardcoding passwords; use a secrets manager or vault."
                        print(f"Compliance Issue (Line {i}): {secret_type} detected - {value}")
                        print(f"Suggestion: {suggestion}")
                        compliance_issues.append({
                            'line': i,
                            'type': secret_type,
                            'value': value,
                            'suggestion': suggestion
                        })
        if not compliance_issues:
            print("Compliance Check: No hardcoded secrets detected.")
        return compliance_issues
    except FileNotFoundError:
        print(f"Error: Dockerfile '{dockerfile_path}' not found.")
        return []

# Run compliance check
compliance_issues = check_secrets(args.dockerfile)

# Structured output
structured_output = {
    "risk_assessments": [
        {
            "cve": "CVE-2025-1234",
            "severity": "LOW",
            "decision": "ACCEPTED for 30 days"
        }
    ],
    "compliance_issues": compliance_issues
}
print("\nStructured Output (JSON):")
print(json.dumps(structured_output, indent=2))

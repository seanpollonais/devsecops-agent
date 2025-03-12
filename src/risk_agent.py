import json
import yaml
import re
import time
import os

def load_file(file_path, file_type):
    try:
        with open(file_path, 'r') as file:
            return json.load(file) if file_type == 'json' else yaml.safe_load(file)
    except FileNotFoundError:
        print(f"Error: {file_type} file '{file_path}' not found.")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON in '{file_path}'.")
        return None
    except yaml.YAMLError:
        print(f"Error: Invalid YAML in '{file_path}'.")
        return None

# Load Trivy JSON file
trivy_data = load_file('../trivy.json', 'json')
if not trivy_data:
    exit(1)

# Load policy YAML file
policy_data = load_file('../policy.yaml', 'yaml')
if not policy_data:
    exit(1)

# Extract risk data
vulnerabilities = trivy_data.get('Vulnerabilities', [])
if not vulnerabilities:
    print("Warning: No vulnerabilities found in Trivy data.")
    exit(0)

max_severity = policy_data['risk_policies']['max_severity']
auto_accept_days = policy_data['risk_policies']['auto_accept_days']
ignore_cves = policy_data['risk_policies']['ignore_cves']

# Define severity levels for comparison
SEVERITY_ORDER = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}

# Structured output
results = {
    "risk_assessments": [],
    "compliance_issues": []
}

# Risk acceptance logic
for vuln in vulnerabilities:
    vuln_id = vuln['VulnerabilityID']
    severity = vuln['Severity']
    
    if vuln_id in ignore_cves:
        decision = "IGNORED"
    elif SEVERITY_ORDER.get(severity.upper(), 99) <= SEVERITY_ORDER.get(max_severity.upper(), 99):
        decision = f"ACCEPTED for {auto_accept_days} days"
    else:
        decision = "ESCALATE"
    
    print(f"{vuln_id}: Severity {severity} -> {decision}")
    results["risk_assessments"].append({
        "cve": vuln_id,
        "severity": severity,
        "decision": decision
    })

# Compliance check for Dockerfile
def check_secrets(file_path):
    secret_patterns = {
        'AWS_ACCESS_KEY': {
            'pattern': r'AWS_ACCESS_KEY=AKIA[0-9A-Z]{10,16}',
            'suggestion': "Use AWS Secrets Manager or environment variables for AWS credentials."
        },
        'PASSWORD': {
            'pattern': r'PASSWORD=["\']?\w{8,}',
            'suggestion': "Avoid hardcoding passwords; use a secrets manager or vault."
        },
        'API_KEY': {
            'pattern': r'API_KEY=["\']?[0-9a-zA-Z]{32}',
            'suggestion': "Store API keys securely in a secrets manager like HashiCorp Vault."
        }
    }
    
    issues_found = False
    try:
        # Ensure file is not being written by another process
        time.sleep(1)  # Wait for any concurrent writes
        with open(file_path, 'r') as file:
            for line_number, line in enumerate(file, 1):
                print(f"Debug - Line {line_number}: {line.strip()}")
                for key, config in secret_patterns.items():
                    secrets = re.findall(config['pattern'], line, re.IGNORECASE)
                    if secrets:
                        issues_found = True
                        for secret in secrets:
                            print(f"Compliance Issue (Line {line_number}): {key} detected - {secret}")
                            print(f"Suggestion: {config['suggestion']}")
                            results["compliance_issues"].append({
                                "line": line_number,
                                "type": key,
                                "value": secret,
                                "suggestion": config['suggestion']
                            })
        if not issues_found:
            print("Compliance Check: No hardcoded secrets detected.")
    except FileNotFoundError:
        print(f"Error: Dockerfile '{file_path}' not found.")
    except Exception as e:
        print(f"Error checking Dockerfile: {e}")

# Run compliance check
check_secrets('../Dockerfile')

# Print structured JSON output
print("\nStructured Output (JSON):")
print(json.dumps(results, indent=2))
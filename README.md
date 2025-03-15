# DevSecOps Agent

A minimal viable product (MVP) for a DevSecOps agent that performs risk acceptance and compliance checks.

## Features
- Risk acceptance for CVEs using Trivy scan results and a policy file.
- Compliance checks for secrets in Dockerfiles.

## Usage
Run locally:
```bash
python3 src/risk_agent.py
```
Run in Docker:
```bash
docker build -f Dockerfile -t devsecops-agent .
docker run --rm -v $(pwd):/app devsecops-agent
```
## Installation
- **Prerequisites**: Docker, Python 3.9+, pip.
- **Local Setup**: Install dependencies: `pip3 install pyyaml`.
- **Docker Setup**: Build and run: `docker build -f Dockerfile -t devsecops-agent .` and `docker run --rm -v $(pwd):/app devsecops-agent`.

## Contributing
- Fork the repository.
- Create a branch: `git checkout -b feature-branch`.
- Commit changes: `git commit -m "Add feature"`.
- Push and submit a pull request.

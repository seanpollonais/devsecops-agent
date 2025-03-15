FROM alpine:latest
ENV AWS_ACCESS_KEY=AKIA1234567890
ENV PASSWORD=supersecret123
RUN apk add --no-cache python3 py3-pip py3-yaml
COPY . /app
WORKDIR /app
CMD ["python3", "src/risk_agent.py"]

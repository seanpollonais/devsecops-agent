FROM alpine:latest
RUN apk add --no-cache python3 py3-pip py3-yaml
COPY . /app
WORKDIR /app
CMD ["python3", "src/risk_agent.py"]

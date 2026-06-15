# Self-contained image for judges: installs the pre-existing logflip engine and
# this agent, generates the synthetic demo case, and runs the agent (deterministic
# policy driver, no API key required). For the LLM-driven path, set
# ANTHROPIC_API_KEY and override the command with --driver claude, or set
# OPENAI_API_KEY and use --driver openai.
FROM python:3.11-slim

# git is needed only to install the pre-existing logflip engine from its public repo.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install the engine first (pre-existing component), then the agent.
RUN pip install --no-cache-dir "git+https://github.com/javierdejesusda/logflip-closed"
COPY . /app
RUN pip install --no-cache-dir .

# Generate the reproducible synthetic demo case at build time.
RUN python cases/demo_stomp/generate.py

# Default run: scan, investigate, self-correct on the anomaly, write the trail.
CMD ["python", "-m", "sift_agent", \
     "--image", "cases/demo_stomp/case.img", \
     "--usnjrnl-record", "42", \
     "--log", "logs/session.jsonl", \
     "--leaf-dir", "cases/demo_stomp/leaves"]

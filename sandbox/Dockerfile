FROM python:3.12-slim

# Single-use, least-privilege extraction environment (report Section 10.1)
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --uid 10001 extractor
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

USER extractor

# Default: fuzz the independent parser against the mounted evidence file.
CMD ["python", "-m", "sandbox.fuzz_parser_b", "--input", "/input/sample_messages.db", "--out", "/out"]

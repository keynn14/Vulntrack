FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

ENV PORT=8085
EXPOSE 8085

# Mount the Greenbone gvmd Unix socket at /run/gvmd/gvmd.sock and pass secrets via environment variables.
CMD ["gunicorn", "--bind", "0.0.0.0:8085", "--workers", "2", "--timeout", "120", "app:app"]

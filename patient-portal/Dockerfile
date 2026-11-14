FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py entrypoint.sh ./
COPY templates ./templates
COPY static ./static

RUN useradd -m ctfuser && chmod 755 /app/entrypoint.sh

EXPOSE 5000

# Single worker on purpose: patient data is held in memory per instance.
CMD ["/app/entrypoint.sh"]

FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .
COPY lib/ lib/
COPY data/ data/

ENTRYPOINT ["python3", "server.py"]

FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8765

ENV NETMON_USER=admin
ENV NETMON_PASS=netmon2026
ENV NETMON_PORT=8765

CMD ["python3", "server.py"]

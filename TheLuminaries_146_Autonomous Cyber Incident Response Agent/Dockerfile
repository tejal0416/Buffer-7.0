FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends gcc g++ libgomp1 \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY ir_agent /app/ir_agent
COPY config /app/config
COPY runbooks /app/runbooks

EXPOSE 8000

CMD ["uvicorn", "ir_agent.main:app", "--host", "0.0.0.0", "--port", "8000"]

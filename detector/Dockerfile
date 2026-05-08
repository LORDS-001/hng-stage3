FROM python:3.11-alpine

WORKDIR /app

# Install build dependencies for psutil
RUN apk add --no-cache gcc musl-dev linux-headers

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN adduser -D appuser
USER appuser

EXPOSE 9000

CMD ["python", "main.py"]

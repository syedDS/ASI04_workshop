FROM python:3.11-slim

WORKDIR /app

# Install dependencies
RUN pip install flask requests chromadb

# Copy application
COPY app.py .
COPY mcp_ecosystem.py .

# Create directories
RUN mkdir -p /app/logs

EXPOSE 5050

CMD ["python", "app.py"]

FROM python:3.11-slim
WORKDIR /app
RUN pip install aiohttp httpx
COPY server.py .
EXPOSE 8771
CMD ["python", "server.py"]

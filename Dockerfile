FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir "bcrypt<4"

# Copy project
COPY . .

EXPOSE 8000

CMD ["python", "run.py"]

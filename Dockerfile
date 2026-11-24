FROM mcr.microsoft.com/playwright/python:v1.49.1-jammy
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
ENV HOST=0.0.0.0 PORT=7860 NO_SANDBOX=1
EXPOSE 7860
CMD ["python", "app.py"]

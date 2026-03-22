FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn insight.wsgi:application --bind 0.0.0.0:8000 --worker-class gevent --workers 4 --worker-connections 100 --timeout 120"]

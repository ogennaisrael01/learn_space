# Builder Stage
FROM python:3.11-slim-bookworm AS builder

# Install curl
RUN apt-get update  && apt-get install -y curl


WORKDIR /app

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

#  Copy the Django project  and install dependencies
COPY requirements.txt  /app/
 
# run this command to install all dependencies 
RUN pip install --no-cache-dir -r requirements.txt
 
# Copy the Django project to the container
COPY . /app/
 
# Expose the Django port
EXPOSE 8000

# Run Django’s development server
CMD python manage.py migrate && python manage.py runserver 0.0.0.0:8000

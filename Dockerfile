# Builder Stage
FROM python:3.12.3-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install curl -y


COPY . .

COPY entry_point /app
RUN chmod +x ./entry_point

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

#  Copy the Django project  and install dependencies
COPY requirements.txt  /app


# run this command to install all dependencies 
RUN pip install --no-cache -r requirements.txt
 
# Copy the Django project to the container
COPY . /app
 
# Expose Django development port
EXPOSE 8000

# Run entrypoint
CMD ["sh", "./entry_point"]


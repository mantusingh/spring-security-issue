#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

# Clean and build the Maven project
echo "Running mvn clean..."
mvn clean

echo "Running mvn install..."
mvn install

# Build the Docker image
echo "Building Docker image..."
docker build -t spring-security-issue . --no-cache

# Run the Docker container
echo "Running Docker container..."
docker run -p 8080:8080 spring-security-issue
#!/bin/bash

# Deploy script for Go Network Exporter with Docker
set -e

echo "🚀 Deploying Go Network Exporter with Docker..."

# Stop existing container if running
echo "⏹️  Stopping existing container..."
docker-compose down || true

# Clean up old images
echo "🧹 Cleaning up old images..."
docker image prune -f

# Build and start the container
echo "🔨 Building and starting container..."
docker-compose up -d --build

# Wait for container to be healthy
echo "⏳ Waiting for container to be healthy..."
timeout 60 bash -c 'until docker-compose ps | grep -q "healthy"; do sleep 2; done' || {
    echo "❌ Container failed to become healthy"
    docker-compose logs
    exit 1
}

# Show status
echo "✅ Deployment successful!"
echo "📊 Container status:"
docker-compose ps

echo "🩺 Health check:"
curl -f http://localhost:9115/health || echo "❌ Health check failed"

echo "🔍 Test ICMP probe:"
curl -f "http://localhost:9115/probe?module=icmp&target=8.8.8.8" | head -20

echo "📋 Container logs:"
docker-compose logs --tail=20

echo "🎉 Go Network Exporter is running on http://localhost:9115"
echo "Use 'docker-compose logs -f' to follow logs"
echo "Use 'docker-compose down' to stop"
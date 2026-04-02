# OpenAPI-First API - Docker Image
# Runs TypeScript directly using tsx runtime (no transpilation needed)

FROM node:24-slim

# Install OpenSSL and other runtime dependencies
RUN apt-get update && apt-get install -y \
  openssl \
  ca-certificates \
  curl \
  && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy package files first for better Docker layer caching
COPY package*.json ./

# Install ALL dependencies (including devDependencies for tsx)
# Note: tsx is in devDependencies and required to run TypeScript directly
RUN npm ci

# Copy source code and configuration files
COPY . .

# Expose the port the app runs on
EXPOSE 3000

# Create non-root user for security
RUN groupadd --gid 1001 nodejs
RUN useradd --uid 1001 --gid nodejs --shell /bin/bash --create-home nodejs

# Change ownership of the app directory
RUN chown -R nodejs:nodejs /app
USER nodejs

# Health check to verify the application is running
HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=40s \
  CMD curl -f http://localhost:3000/health || exit 1

# Start the application with tsx (runs TypeScript directly)
CMD ["node", "--import=tsx", "src/index.ts"]

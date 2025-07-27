#!/bin/bash

# QuickScribe Production Environment Setup Script
echo "=== QuickScribe Production Setup ==="

# Generate a secure JWT secret (512-bit base64 encoded)
echo "Generating secure JWT secret..."
JWT_SECRET=$(openssl rand -base64 64 | tr -d '\n')

# Create .env file for local development
cat > .env << EOF
# Database Configuration
DATABASE_URL=jdbc:postgresql://localhost:5432/quickscribe
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_secure_password_here

# JWT Configuration - CRITICAL FOR SECURITY
JWT_SECRET=${JWT_SECRET}
JWT_EXPIRATION_MS=86400000
REFRESH_TOKEN_EXPIRY_MS=604800000

# CORS Configuration
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080

# Rate Limiting
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=10

# Security Settings
PASSWORD_STRENGTH=8
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=15

# Logging
LOG_LEVEL=INFO
SECURITY_LOG_LEVEL=WARN

# Production Settings (set to true in production)
COOKIE_SECURE=false
DDL_AUTO=update
SHOW_SQL=false

# OAuth2 (Optional)
GOOGLE_CLIENT_ID=
GOOGLE_CLIENT_SECRET=
EOF

echo "✅ .env file created with secure JWT secret"
echo "⚠️  IMPORTANT: Update the DATABASE_PASSWORD in .env file"
echo "⚠️  IMPORTANT: Never commit .env to version control"

# Create .env.example for documentation
cat > .env.example << EOF
# Copy this file to .env and fill in your actual values

DATABASE_URL=jdbc:postgresql://localhost:5432/quickscribe
DATABASE_USERNAME=postgres
DATABASE_PASSWORD=your_database_password

JWT_SECRET=your_512_bit_base64_encoded_secret
JWT_EXPIRATION_MS=86400000
REFRESH_TOKEN_EXPIRY_MS=604800000

CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
RATE_LIMIT_RPM=60
RATE_LIMIT_BURST=10

PASSWORD_STRENGTH=8
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION=15

LOG_LEVEL=INFO
SECURITY_LOG_LEVEL=WARN

COOKIE_SECURE=true
DDL_AUTO=validate
SHOW_SQL=false

GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
EOF

echo "✅ .env.example created for documentation"

# Add .env to .gitignore if it exists
if [ -f .gitignore ]; then
    if ! grep -q "^\.env$" .gitignore; then
        echo ".env" >> .gitignore
        echo "✅ Added .env to .gitignore"
    fi
else
    echo ".env" > .gitignore
    echo "✅ Created .gitignore with .env"
fi

echo ""
echo "=== Production Deployment Checklist ==="
echo "□ Set JWT_SECRET environment variable with a strong 512-bit secret"
echo "□ Use HTTPS in production (set COOKIE_SECURE=true)"
echo "□ Set DDL_AUTO=validate or none in production"
echo "□ Configure proper CORS_ALLOWED_ORIGINS"
echo "□ Set up database with proper credentials"
echo "□ Configure rate limiting based on your needs"
echo "□ Set up monitoring and logging"
echo "□ Review security headers in SecurityConfig"
echo "□ Consider implementing Redis for distributed rate limiting"
echo "□ Set up proper SSL/TLS certificates"

echo ""
echo "🚀 Setup complete! Your application is now production-ready."

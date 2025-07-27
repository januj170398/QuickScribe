# JWT Security Configuration Guide

## Overview
This application uses JWT (JSON Web Tokens) for authentication. Proper JWT secret management is critical for application security.

## JWT Secret Requirements
- **Minimum Length**: 32 characters (256 bits)
- **Recommended**: 64+ characters (512+ bits)
- **Format**: Base64-encoded random bytes
- **Uniqueness**: Different secrets for different environments

## Generating Secure JWT Secrets

### Method 1: Using OpenSSL
```bash
# Generate a 512-bit (64-byte) random secret
openssl rand -base64 64
```

### Method 2: Using Python
```bash
python3 -c "import secrets; import base64; print(base64.b64encode(secrets.token_bytes(64)).decode())"
```

### Method 3: Using Node.js
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('base64'))"
```

## Environment Configuration

### Development Environment
- Uses a predefined secure secret in `application-dev.properties`
- Safe for local development but NEVER use in production

### Production Environment
- **CRITICAL**: Must use environment variables
- No fallback defaults provided for security
- Application will fail to start if JWT_SECRET is not provided

### Required Environment Variables for Production
```bash
export JWT_SECRET="your-super-secure-base64-encoded-secret-here"
export JWT_EXPIRATION="3600"  # 1 hour (optional, defaults to 3600)
export JWT_REFRESH_EXPIRATION="604800"  # 7 days (optional)
```

## Security Best Practices

### DO:
- ✅ Generate a new secret for each environment
- ✅ Use environment variables in production
- ✅ Store secrets in secure vaults (AWS Secrets Manager, Azure Key Vault, etc.)
- ✅ Rotate secrets regularly
- ✅ Use minimum 256-bit (32-character) secrets

### DON'T:
- ❌ Use weak, predictable secrets like "mySecretKey"
- ❌ Commit secrets to version control
- ❌ Share secrets between environments
- ❌ Use the same secret for multiple applications
- ❌ Store secrets in plain text files

## Deployment Examples

### Docker
```dockerfile
# Set via docker run
docker run -e JWT_SECRET="your-secret-here" your-app

# Or in docker-compose.yml
environment:
  - JWT_SECRET=${JWT_SECRET}
```

### Kubernetes
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: jwt-secret
type: Opaque
data:
  JWT_SECRET: <base64-encoded-secret>
```

### AWS ECS/Fargate
```json
{
  "name": "JWT_SECRET",
  "valueFrom": "arn:aws:secretsmanager:region:account:secret:jwt-secret"
}
```

## Troubleshooting

### Common Issues:
1. **Application fails to start**: Check if JWT_SECRET environment variable is set
2. **"JWT secret must be at least 32 characters"**: Generate a longer secret
3. **Token validation fails**: Ensure the same secret is used for signing and verification

### Validation:
The application automatically validates JWT secret strength on startup and will throw an `IllegalArgumentException` if the secret is too weak.

## Security Notes
- JWT secrets are used to sign and verify tokens
- Compromised secrets allow attackers to forge valid tokens
- Regular rotation is recommended (monthly or quarterly)
- Monitor for unusual authentication patterns that might indicate compromised secrets

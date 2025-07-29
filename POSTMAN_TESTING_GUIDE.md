# QuickScribe API Testing with Postman

## Setup Instructions

1. **Start your Spring Boot application**:
   ```bash
   cd /Users/anujjain/work/QuickScribe
   mvn spring-boot:run -Dspring.profiles.active=dev
   ```

2. **Base URL**: `http://localhost:8082` (as configured in dev profile)

## 1. User Registration Testing

### POST `/api/auth/register`

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
    "name": "John Doe",
    "email": "john.doe@example.com",
    "password": "password123"
}
```

**Expected Response (201 Created):**
```json
{
    "message": "User registered successfully",
    "success": true
}
```

**Test Cases:**
- Valid registration
- Duplicate email (should return 400)
- Invalid email format (should return 400)
- Weak password (should return 400)

---

## 2. User Login Testing

### POST `/api/auth/login`

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
    "email": "john.doe@example.com",
    "password": "password123"
}
```

**Expected Response (200 OK):**
```json
{
    "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
    "tokenType": "Bearer",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Test Cases:**
- Valid credentials
- Invalid email (should return 401)
- Invalid password (should return 401)
- Non-existent user (should return 401)

---

## 3. Protected Endpoint Testing

### GET `/api/protected-endpoint` (Example)

**Headers:**
```
Authorization: Bearer YOUR_ACCESS_TOKEN_HERE
Content-Type: application/json
```

**Expected Response (200 OK):**
```json
{
    "message": "Access granted",
    "user": "john.doe@example.com"
}
```

**Test Cases:**
- Valid token
- Expired token (should return 401)
- Invalid token (should return 401)
- Missing Authorization header (should return 401)

---

## 4. Refresh Token Testing

### POST `/api/auth/refresh`

**Headers:**
```
Content-Type: application/json
```

**Body (JSON):**
```json
{
    "refreshToken": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Expected Response (200 OK):**
```json
{
    "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
    "tokenType": "Bearer",
    "refreshToken": "550e8400-e29b-41d4-a716-446655440001"
}
```

**Test Cases:**
- Valid refresh token
- Expired refresh token (should return 403)
- Invalid refresh token (should return 403)

---

## 5. Google OAuth2 Testing (Browser Required)

### Step 1: Initiate OAuth2 Flow
**GET** `http://localhost:8082/oauth2/authorize/google`

This will redirect to Google's authentication page. You must use a browser for this step.

### Step 2: Test the Callback
After successful Google authentication, you'll be redirected to:
`http://localhost:3000/auth/oauth2/redirect?token=JWT_TOKEN&refreshToken=REFRESH_TOKEN`

### Step 3: Test the Tokens
Use the tokens received from the OAuth2 callback in subsequent API calls.

---

## 6. Postman Collection Setup

### Environment Variables
Create a Postman environment with these variables:

```
BASE_URL: http://localhost:8082
ACCESS_TOKEN: (set after login)
REFRESH_TOKEN: (set after login)
```

### Auto-Update Tokens Script
Add this to your login request's **Tests** tab:

```javascript
if (pm.response.code === 200) {
    const response = pm.response.json();
    pm.environment.set("ACCESS_TOKEN", response.accessToken);
    pm.environment.set("REFRESH_TOKEN", response.refreshToken);
    console.log("Tokens updated successfully");
}
```

---

## 7. Error Testing Scenarios

### Test Invalid JSON Format
**Body:**
```json
{
    "email": "invalid-json"
    // Missing closing brace
```

### Test SQL Injection Attempts
**Body:**
```json
{
    "email": "'; DROP TABLE users; --",
    "password": "password123"
}
```

### Test XSS Attempts
**Body:**
```json
{
    "name": "<script>alert('xss')</script>",
    "email": "test@example.com",
    "password": "password123"
}
```

---

## 8. CORS Testing

### Pre-flight Request
**OPTIONS** `/api/auth/login`

**Headers:**
```
Origin: http://localhost:3000
Access-Control-Request-Method: POST
Access-Control-Request-Headers: Content-Type
```

**Expected Response Headers:**
```
Access-Control-Allow-Origin: http://localhost:3000
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS,PATCH
Access-Control-Allow-Headers: *
Access-Control-Allow-Credentials: true
```

---

## 9. Rate Limiting Testing

Send multiple requests rapidly to test rate limiting:

### Bulk Test Script (Postman Tests tab)
```javascript
for (let i = 0; i < 10; i++) {
    pm.sendRequest({
        url: pm.environment.get("BASE_URL") + "/api/auth/login",
        method: 'POST',
        header: {
            'Content-Type': 'application/json'
        },
        body: {
            mode: 'raw',
            raw: JSON.stringify({
                email: "test@example.com",
                password: "wrongpassword"
            })
        }
    }, function (err, res) {
        console.log(`Request ${i + 1}: Status ${res.code}`);
    });
}
```

---

## 10. Health Check Endpoints

### GET `/actuator/health` (if Spring Actuator is enabled)
Test application health status.

### GET `/api/public/status`
Test public endpoints that don't require authentication.

---

## Common HTTP Status Codes

- **200**: Success
- **201**: Created (registration)
- **400**: Bad Request (validation errors)
- **401**: Unauthorized (invalid credentials/token)
- **403**: Forbidden (expired token, insufficient permissions)
- **404**: Not Found
- **429**: Too Many Requests (rate limiting)
- **500**: Internal Server Error

---

## Tips for Effective Testing

1. **Use Postman Collections**: Organize related requests
2. **Set up Environment Variables**: For easy switching between dev/prod
3. **Use Pre-request Scripts**: To automatically set headers
4. **Add Tests**: Validate response structure and status codes
5. **Test Edge Cases**: Empty payloads, special characters, long strings
6. **Monitor Response Times**: Check API performance
7. **Test Concurrent Requests**: Use Postman Runner for load testing

---

## Sample Postman Test Scripts

### For Login Request:
```javascript
pm.test("Status code is 200", function () {
    pm.response.to.have.status(200);
});

pm.test("Response has access token", function () {
    const response = pm.response.json();
    pm.expect(response).to.have.property('accessToken');
    pm.expect(response.accessToken).to.be.a('string');
});

pm.test("Response time is less than 2000ms", function () {
    pm.expect(pm.response.responseTime).to.be.below(2000);
});
```

### For Protected Endpoints:
```javascript
pm.test("Unauthorized without token", function () {
    if (!pm.request.headers.get("Authorization")) {
        pm.response.to.have.status(401);
    }
});
```

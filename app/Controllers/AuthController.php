<?php

declare(strict_types=1);

namespace App\Controllers;

use App\Services\JwtService;
use Monolog\Logger;
use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * OWASP A02: Cryptographic Failures - bcrypt password hashing
 * OWASP A03: Injection - prepared statements only
 * OWASP A07: Identification and Authentication Failures
 */
class AuthController
{
    private PDO $db;
    private JwtService $jwt;
    private Logger $logger;

    public function __construct(PDO $db, JwtService $jwt, Logger $logger)
    {
        $this->db = $db;
        $this->jwt = $jwt;
        $this->logger = $logger;
    }

    /**
     * POST /api/v1/auth/register
     */
    public function register(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();

        // Input validation
        $errors = $this->validateRegistration($body);
        if (!empty($errors)) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Validation failed', 'errors' => $errors], 422);
        }

        $name = trim($body['name']);
        $email = strtolower(trim($body['email']));
        $password = $body['password'];

        // OWASP A03: Check for existing user with prepared statement
        $stmt = $this->db->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
        $stmt->execute(['email' => $email]);

        if ($stmt->fetch()) {
            // OWASP A07: Don't reveal whether email exists (generic message)
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Registration failed. Please try again.'], 409);
        }

        // OWASP A02: Hash password with bcrypt (cost factor 12)
        $hashedPassword = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);

        $stmt = $this->db->prepare(
            'INSERT INTO users (name, email, password, role, created_at, updated_at) VALUES (:name, :email, :password, :role, NOW(), NOW())'
        );
        $stmt->execute([
            'name' => $name,
            'email' => $email,
            'password' => $hashedPassword,
            'role' => 'user',
        ]);

        $userId = (int) $this->db->lastInsertId();

        // OWASP A09: Log successful registration
        $this->logger->info('User registered', ['user_id' => $userId, 'email' => $email]);

        $accessToken = $this->jwt->generateToken($userId, $email, 'user');
        $refreshToken = $this->jwt->generateRefreshToken($userId);

        return $this->jsonResponse($response, [
            'success' => true,
            'message' => 'Registration successful',
            'data' => [
                'user' => ['id' => $userId, 'name' => $name, 'email' => $email, 'role' => 'user'],
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
            ],
        ], 201);
    }

    /**
     * POST /api/v1/auth/login
     */
    public function login(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        $email = strtolower(trim($body['email'] ?? ''));
        $password = $body['password'] ?? '';

        if (empty($email) || empty($password)) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Email and password are required.'], 422);
        }

        // OWASP A03: Prepared statement
        $stmt = $this->db->prepare('SELECT id, name, email, password, role FROM users WHERE email = :email AND active = 1 LIMIT 1');
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        // OWASP A07: Constant-time password comparison & generic error message
        if (!$user || !password_verify($password, $user['password'])) {
            $this->logger->warning('Failed login attempt', ['type' => 'SECURITY', 'email' => $email, 'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown']);
            // OWASP A07: Don't reveal whether email or password is wrong
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Invalid credentials.'], 401);
        }

        // OWASP A02: Rehash if bcrypt cost has changed
        if (password_needs_rehash($user['password'], PASSWORD_BCRYPT, ['cost' => 12])) {
            $newHash = password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
            $stmt = $this->db->prepare('UPDATE users SET password = :password WHERE id = :id');
            $stmt->execute(['password' => $newHash, 'id' => $user['id']]);
        }

        $accessToken = $this->jwt->generateToken((int) $user['id'], $user['email'], $user['role']);
        $refreshToken = $this->jwt->generateRefreshToken((int) $user['id']);

        // OWASP A09: Log successful login
        $this->logger->info('User logged in', ['user_id' => $user['id']]);

        return $this->jsonResponse($response, [
            'success' => true,
            'message' => 'Login successful',
            'data' => [
                'user' => ['id' => (int) $user['id'], 'name' => $user['name'], 'email' => $user['email'], 'role' => $user['role']],
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
            ],
        ]);
    }

    /**
     * POST /api/v1/auth/refresh
     */
    public function refresh(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        $refreshToken = $body['refresh_token'] ?? '';

        if (empty($refreshToken)) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Refresh token is required.'], 422);
        }

        try {
            $payload = $this->jwt->validateRefreshToken($refreshToken);
        } catch (\Exception $e) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Invalid or expired refresh token.'], 401);
        }

        $stmt = $this->db->prepare('SELECT id, email, role FROM users WHERE id = :id AND active = 1 LIMIT 1');
        $stmt->execute(['id' => $payload->sub]);
        $user = $stmt->fetch();

        if (!$user) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'User not found.'], 401);
        }

        $newAccessToken = $this->jwt->generateToken((int) $user['id'], $user['email'], $user['role']);
        $newRefreshToken = $this->jwt->generateRefreshToken((int) $user['id']);

        return $this->jsonResponse($response, [
            'success' => true,
            'message' => 'Token refreshed',
            'data' => [
                'access_token' => $newAccessToken,
                'refresh_token' => $newRefreshToken,
                'token_type' => 'Bearer',
            ],
        ]);
    }

    /**
     * GET /api/v1/auth/me (protected)
     */
    public function me(Request $request, Response $response): Response
    {
        $userId = $request->getAttribute('user_id');

        $stmt = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $userId]);
        $user = $stmt->fetch();

        if (!$user) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'User not found.'], 404);
        }

        $user['id'] = (int) $user['id'];

        return $this->jsonResponse($response, [
            'success' => true,
            'data' => $user,
        ]);
    }

    /**
     * POST /api/v1/auth/logout (protected)
     */
    public function logout(Request $request, Response $response): Response
    {
        // With stateless JWT, logout is handled client-side by discarding the token.
        // For enhanced security, implement a token blacklist table.
        $userId = $request->getAttribute('user_id');
        $this->logger->info('User logged out', ['user_id' => $userId]);

        return $this->jsonResponse($response, [
            'success' => true,
            'message' => 'Logged out successfully',
        ]);
    }

    private function validateRegistration(array $body): array
    {
        $errors = [];

        if (empty($body['name']) || strlen(trim($body['name'])) < 2) {
            $errors['name'] = 'Name must be at least 2 characters.';
        }
        if (empty($body['email']) || !filter_var($body['email'], FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'A valid email address is required.';
        }
        if (empty($body['password']) || strlen($body['password']) < 8) {
            $errors['password'] = 'Password must be at least 8 characters.';
        }
        // OWASP A07: Enforce password complexity
        if (!empty($body['password']) && !preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $body['password'])) {
            $errors['password'] = 'Password must contain at least one uppercase letter, one lowercase letter, and one number.';
        }
        if (strlen($body['name'] ?? '') > 255 || strlen($body['email'] ?? '') > 255) {
            $errors['input'] = 'Input exceeds maximum length.';
        }

        return $errors;
    }

    private function jsonResponse(Response $response, array $data, int $status = 200): Response
    {
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP));
        return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
    }
}

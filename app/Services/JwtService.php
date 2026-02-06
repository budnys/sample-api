<?php

declare(strict_types=1);

namespace App\Services;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use Firebase\JWT\ExpiredException;

/**
 * OWASP A02: Cryptographic Failures - Secure JWT token management
 * OWASP A07: Identification and Authentication Failures
 */
class JwtService
{
    private string $secret;
    private string $algorithm;
    private int $expiry;
    private int $refreshExpiry;

    public function __construct(string $secret, string $algorithm = 'HS256', int $expiry = 3600, int $refreshExpiry = 604800)
    {
        if (strlen($secret) < 32) {
            throw new \RuntimeException('JWT secret must be at least 32 characters long.');
        }

        $this->secret = $secret;
        $this->algorithm = $algorithm;
        $this->expiry = $expiry;
        $this->refreshExpiry = $refreshExpiry;
    }

    /**
     * Generate an access token for a user
     */
    public function generateToken(int $userId, string $email, string $role = 'user'): string
    {
        $now = time();

        $payload = [
            'iss' => $_ENV['APP_URL'] ?? 'secure-api',
            'sub' => $userId,
            'email' => $email,
            'role' => $role,
            'iat' => $now,
            'exp' => $now + $this->expiry,
            'jti' => bin2hex(random_bytes(16)),
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Generate a refresh token with longer expiry
     */
    public function generateRefreshToken(int $userId): string
    {
        $now = time();

        $payload = [
            'iss' => $_ENV['APP_URL'] ?? 'secure-api',
            'sub' => $userId,
            'type' => 'refresh',
            'iat' => $now,
            'exp' => $now + $this->refreshExpiry,
            'jti' => bin2hex(random_bytes(16)),
        ];

        return JWT::encode($payload, $this->secret, $this->algorithm);
    }

    /**
     * Decode and validate a JWT token
     *
     * @throws ExpiredException
     * @throws \Exception
     */
    public function decode(string $token): object
    {
        return JWT::decode($token, new Key($this->secret, $this->algorithm));
    }

    /**
     * Validate that a token is a refresh token
     */
    public function validateRefreshToken(string $token): object
    {
        $payload = $this->decode($token);

        if (!isset($payload->type) || $payload->type !== 'refresh') {
            throw new \InvalidArgumentException('Token is not a valid refresh token.');
        }

        return $payload;
    }
}

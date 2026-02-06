<?php

declare(strict_types=1);

namespace Tests\Services;

use App\Services\JwtService;
use Firebase\JWT\ExpiredException;
use PHPUnit\Framework\TestCase;

class JwtServiceTest extends TestCase
{
    private string $secret = 'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';
    private JwtService $jwt;

    protected function setUp(): void
    {
        $this->jwt = new JwtService($this->secret, 'HS256', 3600, 604800);
    }

    public function testConstructorThrowsOnShortSecret(): void
    {
        $this->expectException(\RuntimeException::class);
        $this->expectExceptionMessage('JWT secret must be at least 32 characters long.');
        new JwtService('short');
    }

    public function testConstructorAcceptsValidSecret(): void
    {
        $jwt = new JwtService($this->secret);
        $this->assertInstanceOf(JwtService::class, $jwt);
    }

    public function testConstructorDefaultParameters(): void
    {
        $jwt = new JwtService($this->secret);
        $token = $jwt->generateToken(1, 'test@test.com');
        $payload = $jwt->decode($token);
        $this->assertEquals(1, $payload->sub);
    }

    public function testGenerateTokenReturnsString(): void
    {
        $token = $this->jwt->generateToken(1, 'user@example.com', 'user');
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testGenerateTokenContainsCorrectClaims(): void
    {
        $token = $this->jwt->generateToken(42, 'admin@example.com', 'admin');
        $payload = $this->jwt->decode($token);

        $this->assertEquals(42, $payload->sub);
        $this->assertEquals('admin@example.com', $payload->email);
        $this->assertEquals('admin', $payload->role);
        $this->assertObjectHasProperty('iss', $payload);
        $this->assertObjectHasProperty('iat', $payload);
        $this->assertObjectHasProperty('exp', $payload);
        $this->assertObjectHasProperty('jti', $payload);
        $this->assertEquals($payload->iat + 3600, $payload->exp);
    }

    public function testGenerateTokenDefaultRoleIsUser(): void
    {
        $token = $this->jwt->generateToken(1, 'test@test.com');
        $payload = $this->jwt->decode($token);
        $this->assertEquals('user', $payload->role);
    }

    public function testGenerateRefreshTokenReturnsString(): void
    {
        $token = $this->jwt->generateRefreshToken(1);
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testGenerateRefreshTokenContainsCorrectClaims(): void
    {
        $token = $this->jwt->generateRefreshToken(99);
        $payload = $this->jwt->decode($token);

        $this->assertEquals(99, $payload->sub);
        $this->assertEquals('refresh', $payload->type);
        $this->assertEquals($payload->iat + 604800, $payload->exp);
        $this->assertObjectHasProperty('jti', $payload);
    }

    public function testDecodeValidToken(): void
    {
        $token = $this->jwt->generateToken(5, 'test@test.com', 'user');
        $payload = $this->jwt->decode($token);

        $this->assertEquals(5, $payload->sub);
        $this->assertEquals('test@test.com', $payload->email);
    }

    public function testDecodeInvalidTokenThrowsException(): void
    {
        $this->expectException(\Exception::class);
        $this->jwt->decode('invalid.token.here');
    }

    public function testDecodeTokenWithWrongSecretThrows(): void
    {
        $otherJwt = new JwtService(str_repeat('x', 32));
        $token = $otherJwt->generateToken(1, 'test@test.com');

        $this->expectException(\Exception::class);
        $this->jwt->decode($token);
    }

    public function testDecodeExpiredTokenThrows(): void
    {
        $shortJwt = new JwtService($this->secret, 'HS256', -1, -1);
        $token = $shortJwt->generateToken(1, 'test@test.com');

        $this->expectException(ExpiredException::class);
        $this->jwt->decode($token);
    }

    public function testValidateRefreshTokenSuccess(): void
    {
        $token = $this->jwt->generateRefreshToken(10);
        $payload = $this->jwt->validateRefreshToken($token);

        $this->assertEquals(10, $payload->sub);
        $this->assertEquals('refresh', $payload->type);
    }

    public function testValidateRefreshTokenRejectsAccessToken(): void
    {
        $token = $this->jwt->generateToken(1, 'test@test.com');

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Token is not a valid refresh token.');
        $this->jwt->validateRefreshToken($token);
    }

    public function testValidateRefreshTokenRejectsInvalidToken(): void
    {
        $this->expectException(\Exception::class);
        $this->jwt->validateRefreshToken('garbage.token.data');
    }

    public function testGenerateTokenJtiIsUnique(): void
    {
        $token1 = $this->jwt->generateToken(1, 'test@test.com');
        $token2 = $this->jwt->generateToken(1, 'test@test.com');

        $payload1 = $this->jwt->decode($token1);
        $payload2 = $this->jwt->decode($token2);

        $this->assertNotEquals($payload1->jti, $payload2->jti);
    }

    public function testGenerateRefreshTokenJtiIsUnique(): void
    {
        $token1 = $this->jwt->generateRefreshToken(1);
        $token2 = $this->jwt->generateRefreshToken(1);

        $payload1 = $this->jwt->decode($token1);
        $payload2 = $this->jwt->decode($token2);

        $this->assertNotEquals($payload1->jti, $payload2->jti);
    }
}

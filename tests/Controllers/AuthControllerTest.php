<?php

declare(strict_types=1);

namespace Tests\Controllers;

use App\Controllers\AuthController;
use App\Services\JwtService;
use PHPUnit\Framework\TestCase;
use Tests\TestHelper;

class AuthControllerTest extends TestCase
{
    use TestHelper;

    private \PDO $pdo;
    private JwtService $jwt;
    private \Monolog\Logger $logger;
    private AuthController $controller;

    protected function setUp(): void
    {
        $this->pdo = $this->createMock(\PDO::class);
        $this->jwt = new JwtService(
            'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'
        );
        $this->logger = $this->createMockLogger();
        $this->controller = new AuthController($this->pdo, $this->jwt, $this->logger);
    }

    // --- Register ---

    public function testRegisterValidationFailsOnEmptyBody(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], []);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertArrayHasKey('errors', $body);
    }

    public function testRegisterValidationFailsOnShortName(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'A',
            'email' => 'test@example.com',
            'password' => 'SecurePass1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('name', $body['errors']);
    }

    public function testRegisterValidationFailsOnInvalidEmail(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'John Doe',
            'email' => 'not-an-email',
            'password' => 'SecurePass1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('email', $body['errors']);
    }

    public function testRegisterValidationFailsOnWeakPassword(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'password' => 'weakpass',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('password', $body['errors']);
    }

    public function testRegisterValidationFailsOnShortPassword(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'password' => 'Ab1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('password', $body['errors']);
    }

    public function testRegisterValidationFailsOnExceedingLength(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => str_repeat('A', 256),
            'email' => 'test@example.com',
            'password' => 'SecurePass1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('input', $body['errors']);
    }

    public function testRegisterReturns409WhenEmailExists(): void
    {
        $stmt = $this->createMockStatement(['id' => 1]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'John Doe',
            'email' => 'existing@example.com',
            'password' => 'SecurePass1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(409, $result->getStatusCode());
        $this->assertFalse($body['success']);
    }

    public function testRegisterSuccessReturns201WithTokens(): void
    {
        $checkStmt = $this->createMock(\PDOStatement::class);
        $checkStmt->method('execute')->willReturn(true);
        $checkStmt->method('fetch')->willReturn(false);

        $insertStmt = $this->createMock(\PDOStatement::class);
        $insertStmt->method('execute')->willReturn(true);

        $this->pdo->method('prepare')->willReturnOnConsecutiveCalls($checkStmt, $insertStmt);
        $this->pdo->method('lastInsertId')->willReturn('42');

        $request = $this->createRequest('POST', '/api/v1/auth/register', [], [
            'name' => 'John Doe',
            'email' => 'new@example.com',
            'password' => 'SecurePass1',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->register($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(201, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('Registration successful', $body['message']);
        $this->assertArrayHasKey('access_token', $body['data']);
        $this->assertArrayHasKey('refresh_token', $body['data']);
        $this->assertEquals('Bearer', $body['data']['token_type']);
        $this->assertEquals(42, $body['data']['user']['id']);
        $this->assertEquals('new@example.com', $body['data']['user']['email']);
    }

    // --- Login ---

    public function testLoginFailsOnEmptyCredentials(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/login', [], []);
        $response = $this->createResponse();

        $result = $this->controller->login($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertFalse($body['success']);
    }

    public function testLoginFailsOnInvalidCredentials(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn(false);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/login', [], [
            'email' => 'nonexistent@example.com',
            'password' => 'WrongPass1',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->login($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertEquals('Invalid credentials.', $body['message']);
    }

    public function testLoginFailsOnWrongPassword(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => 1,
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'password' => password_hash('CorrectPass1', PASSWORD_BCRYPT),
            'role' => 'admin',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/login', [], [
            'email' => 'admin@example.com',
            'password' => 'WrongPass1',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->login($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testLoginSuccessReturnsTokens(): void
    {
        $hashedPassword = password_hash('SecurePass1', PASSWORD_BCRYPT, ['cost' => 12]);
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => 1,
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'password' => $hashedPassword,
            'role' => 'admin',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/login', [], [
            'email' => 'admin@example.com',
            'password' => 'SecurePass1',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->login($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('Login successful', $body['message']);
        $this->assertArrayHasKey('access_token', $body['data']);
        $this->assertArrayHasKey('refresh_token', $body['data']);
        $this->assertEquals('Bearer', $body['data']['token_type']);
        $this->assertEquals(1, $body['data']['user']['id']);
        $this->assertEquals('admin', $body['data']['user']['role']);
    }

    public function testLoginRehashesPasswordWhenNeeded(): void
    {
        // Use a low cost hash to trigger rehash
        $hashedPassword = password_hash('SecurePass1', PASSWORD_BCRYPT, ['cost' => 4]);

        $selectStmt = $this->createMock(\PDOStatement::class);
        $selectStmt->method('execute')->willReturn(true);
        $selectStmt->method('fetch')->willReturn([
            'id' => 1,
            'name' => 'User',
            'email' => 'user@example.com',
            'password' => $hashedPassword,
            'role' => 'user',
        ]);

        $updateStmt = $this->createMock(\PDOStatement::class);
        $updateStmt->method('execute')->willReturn(true);

        $this->pdo->method('prepare')->willReturnOnConsecutiveCalls($selectStmt, $updateStmt);

        $request = $this->createRequest('POST', '/api/v1/auth/login', [], [
            'email' => 'user@example.com',
            'password' => 'SecurePass1',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->login($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
    }

    // --- Refresh ---

    public function testRefreshFailsOnMissingToken(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/refresh', [], []);
        $response = $this->createResponse();

        $result = $this->controller->refresh($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertFalse($body['success']);
    }

    public function testRefreshFailsOnInvalidToken(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/refresh', [], [
            'refresh_token' => 'invalid.token.here',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->refresh($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testRefreshFailsOnAccessTokenInsteadOfRefresh(): void
    {
        $accessToken = $this->jwt->generateToken(1, 'test@test.com');

        $request = $this->createRequest('POST', '/api/v1/auth/refresh', [], [
            'refresh_token' => $accessToken,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->refresh($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testRefreshFailsWhenUserNotFound(): void
    {
        $refreshToken = $this->jwt->generateRefreshToken(999);
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn(false);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/refresh', [], [
            'refresh_token' => $refreshToken,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->refresh($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
        $this->assertEquals('User not found.', $body['message']);
    }

    public function testRefreshSuccessReturnsNewTokens(): void
    {
        $refreshToken = $this->jwt->generateRefreshToken(1);
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => 1,
            'email' => 'user@example.com',
            'role' => 'user',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('POST', '/api/v1/auth/refresh', [], [
            'refresh_token' => $refreshToken,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->refresh($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('Token refreshed', $body['message']);
        $this->assertArrayHasKey('access_token', $body['data']);
        $this->assertArrayHasKey('refresh_token', $body['data']);
        $this->assertEquals('Bearer', $body['data']['token_type']);
    }

    // --- Me ---

    public function testMeReturnsUserData(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => '1',
            'name' => 'Admin',
            'email' => 'admin@example.com',
            'role' => 'admin',
            'created_at' => '2026-01-01 00:00:00',
            'updated_at' => '2026-01-01 00:00:00',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('GET', '/api/v1/auth/me', [], null, [], ['user_id' => 1]);
        $response = $this->createResponse();

        $result = $this->controller->me($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals(1, $body['data']['id']);
        $this->assertEquals('Admin', $body['data']['name']);
    }

    public function testMeReturns404WhenUserNotFound(): void
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn(false);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('GET', '/api/v1/auth/me', [], null, [], ['user_id' => 999]);
        $response = $this->createResponse();

        $result = $this->controller->me($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(404, $result->getStatusCode());
    }

    // --- Logout ---

    public function testLogoutReturnsSuccess(): void
    {
        $request = $this->createRequest('POST', '/api/v1/auth/logout', [], null, [], ['user_id' => 1]);
        $response = $this->createResponse();

        $result = $this->controller->logout($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('Logged out successfully', $body['message']);
    }
}

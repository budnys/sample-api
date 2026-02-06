<?php

declare(strict_types=1);

namespace Tests\Middleware;

use App\Middleware\JwtMiddleware;
use App\Services\JwtService;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tests\TestHelper;

class JwtMiddlewareTest extends TestCase
{
    use TestHelper;

    private JwtService $jwt;
    private JwtMiddleware $middleware;

    protected function setUp(): void
    {
        $this->jwt = new JwtService(
            'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2'
        );
        $this->middleware = new JwtMiddleware($this->jwt);
    }

    private function createHandler(?callable $callback = null): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        if ($callback) {
            $handler->method('handle')->willReturnCallback($callback);
        } else {
            $handler->method('handle')->willReturn(new Response());
        }
        return $handler;
    }

    public function testReturns401WhenNoAuthHeader(): void
    {
        $request = $this->createRequest('GET', '/api/v1/auth/me');
        $handler = $this->createHandler();

        $result = $this->middleware->process($request, $handler);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertStringContainsString('Missing or invalid', $body['message']);
        $this->assertEquals('Bearer', $result->getHeaderLine('WWW-Authenticate'));
    }

    public function testReturns401WhenAuthHeaderNotBearer(): void
    {
        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'Basic dXNlcjpwYXNz',
        ]);
        $handler = $this->createHandler();

        $result = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testReturns401WhenBearerTokenEmpty(): void
    {
        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'Bearer ',
        ]);
        $handler = $this->createHandler();

        $result = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testReturns401WhenTokenIsInvalid(): void
    {
        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'Bearer invalid.token.here',
        ]);
        $handler = $this->createHandler();

        $result = $this->middleware->process($request, $handler);
        $body = $this->getResponseBody($result);

        $this->assertEquals(401, $result->getStatusCode());
        $this->assertStringContainsString('Invalid or expired', $body['message']);
    }

    public function testReturns401WhenTokenIsExpired(): void
    {
        $expiredJwt = new JwtService(
            'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2',
            'HS256',
            -1
        );
        $token = $expiredJwt->generateToken(1, 'test@test.com');

        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'Bearer ' . $token,
        ]);
        $handler = $this->createHandler();

        $result = $this->middleware->process($request, $handler);

        $this->assertEquals(401, $result->getStatusCode());
    }

    public function testPassesWithValidToken(): void
    {
        $token = $this->jwt->generateToken(42, 'admin@test.com', 'admin');

        $capturedRequest = null;
        $handler = $this->createHandler(function ($req) use (&$capturedRequest) {
            $capturedRequest = $req;
            return new Response();
        });

        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'Bearer ' . $token,
        ]);

        $result = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertNotNull($capturedRequest);
        $this->assertEquals(42, $capturedRequest->getAttribute('user_id'));

        $payload = $capturedRequest->getAttribute('jwt_payload');
        $this->assertEquals(42, $payload->sub);
        $this->assertEquals('admin@test.com', $payload->email);
        $this->assertEquals('admin', $payload->role);
    }

    public function testBearerMatchIsCaseInsensitive(): void
    {
        $token = $this->jwt->generateToken(1, 'test@test.com');

        $handler = $this->createHandler(function ($req) {
            return new Response();
        });

        $request = $this->createRequest('GET', '/api/v1/auth/me', [
            'Authorization' => 'bearer ' . $token,
        ]);

        $result = $this->middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
    }
}

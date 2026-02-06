<?php

declare(strict_types=1);

namespace Tests\Middleware;

use App\Middleware\CorsMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tests\TestHelper;

class CorsMiddlewareTest extends TestCase
{
    use TestHelper;

    private function createHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response());
        return $handler;
    }

    public function testPreflightReturns204(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['https://example.com'],
            'allowed_methods' => 'GET,POST',
            'allowed_headers' => 'Content-Type,Authorization',
            'max_age' => 3600,
        ]);

        $request = $this->createRequest('OPTIONS', '/', ['Origin' => 'https://example.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(204, $result->getStatusCode());
        $this->assertEquals('https://example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertEquals('GET,POST', $result->getHeaderLine('Access-Control-Allow-Methods'));
        $this->assertEquals('Content-Type,Authorization', $result->getHeaderLine('Access-Control-Allow-Headers'));
        $this->assertEquals('3600', $result->getHeaderLine('Access-Control-Max-Age'));
        $this->assertEquals('true', $result->getHeaderLine('Access-Control-Allow-Credentials'));
        $this->assertEquals('Origin', $result->getHeaderLine('Vary'));
    }

    public function testNormalRequestAddsCorsHeaders(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['https://example.com'],
        ]);

        $request = $this->createRequest('GET', '/', ['Origin' => 'https://example.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals('https://example.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testDisallowedOriginNoCorsHeaders(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['https://example.com'],
        ]);

        $request = $this->createRequest('GET', '/', ['Origin' => 'https://evil.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEmpty($result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testEmptyOriginNoCorsHeaders(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['https://example.com'],
        ]);

        $request = $this->createRequest('GET', '/');
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEmpty($result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testWildcardOriginAllowsAll(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['*'],
        ]);

        $request = $this->createRequest('GET', '/', ['Origin' => 'https://anything.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals('https://anything.com', $result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testEmptyAllowedOriginsBlocksAll(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => [],
        ]);

        $request = $this->createRequest('GET', '/', ['Origin' => 'https://example.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEmpty($result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testDefaultSettingsWhenNoSettingsProvided(): void
    {
        $middleware = new CorsMiddleware([]);

        $request = $this->createRequest('GET', '/', ['Origin' => 'https://example.com']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        // empty allowed_origins defaults = blocks all
        $this->assertEmpty($result->getHeaderLine('Access-Control-Allow-Origin'));
    }

    public function testMultipleAllowedOrigins(): void
    {
        $middleware = new CorsMiddleware([
            'allowed_origins' => ['https://app1.com', 'https://app2.com'],
        ]);

        $request1 = $this->createRequest('GET', '/', ['Origin' => 'https://app1.com']);
        $request2 = $this->createRequest('GET', '/', ['Origin' => 'https://app2.com']);
        $request3 = $this->createRequest('GET', '/', ['Origin' => 'https://app3.com']);
        $handler = $this->createHandler();

        $result1 = $middleware->process($request1, $handler);
        $result2 = $middleware->process($request2, $handler);
        $result3 = $middleware->process($request3, $handler);

        $this->assertEquals('https://app1.com', $result1->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertEquals('https://app2.com', $result2->getHeaderLine('Access-Control-Allow-Origin'));
        $this->assertEmpty($result3->getHeaderLine('Access-Control-Allow-Origin'));
    }
}

<?php

declare(strict_types=1);

namespace Tests\Middleware;

use App\Middleware\SecurityHeadersMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tests\TestHelper;

class SecurityHeadersMiddlewareTest extends TestCase
{
    use TestHelper;

    private SecurityHeadersMiddleware $middleware;

    protected function setUp(): void
    {
        $this->middleware = new SecurityHeadersMiddleware();
    }

    private function createHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response());
        return $handler;
    }

    public function testAddsXContentTypeOptions(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('nosniff', $result->getHeaderLine('X-Content-Type-Options'));
    }

    public function testAddsXFrameOptions(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('DENY', $result->getHeaderLine('X-Frame-Options'));
    }

    public function testAddsXXssProtection(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('0', $result->getHeaderLine('X-XSS-Protection'));
    }

    public function testAddsReferrerPolicy(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('strict-origin-when-cross-origin', $result->getHeaderLine('Referrer-Policy'));
    }

    public function testAddsContentSecurityPolicy(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals("default-src 'none'; frame-ancestors 'none'", $result->getHeaderLine('Content-Security-Policy'));
    }

    public function testAddsStrictTransportSecurity(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('max-age=31536000; includeSubDomains', $result->getHeaderLine('Strict-Transport-Security'));
    }

    public function testAddsCacheControl(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('no-store, no-cache, must-revalidate', $result->getHeaderLine('Cache-Control'));
    }

    public function testAddsPragma(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('no-cache', $result->getHeaderLine('Pragma'));
    }

    public function testAddsPermissionsPolicy(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $this->assertEquals('camera=(), microphone=(), geolocation=()', $result->getHeaderLine('Permissions-Policy'));
    }

    public function testAllHeadersPresentInSingleRequest(): void
    {
        $request = $this->createRequest('GET', '/');
        $result = $this->middleware->process($request, $this->createHandler());

        $expectedHeaders = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Content-Security-Policy',
            'Strict-Transport-Security',
            'Cache-Control',
            'Pragma',
            'Permissions-Policy',
        ];

        foreach ($expectedHeaders as $header) {
            $this->assertTrue($result->hasHeader($header), "Header $header should be present");
        }
    }
}

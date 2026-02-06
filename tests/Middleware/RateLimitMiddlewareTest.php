<?php

declare(strict_types=1);

namespace Tests\Middleware;

use App\Middleware\RateLimitMiddleware;
use PHPUnit\Framework\TestCase;
use Psr\Http\Server\RequestHandlerInterface;
use Slim\Psr7\Response;
use Tests\TestHelper;

class RateLimitMiddlewareTest extends TestCase
{
    use TestHelper;

    private string $storagePath;

    protected function setUp(): void
    {
        $this->storagePath = sys_get_temp_dir() . '/rate_limit_test_' . uniqid();
        mkdir($this->storagePath, 0750, true);
    }

    protected function tearDown(): void
    {
        // Clean up rate limit files
        if (is_dir($this->storagePath)) {
            $files = glob($this->storagePath . '/*.json');
            foreach ($files as $file) {
                unlink($file);
            }
            rmdir($this->storagePath);
        }
    }

    private function createHandler(): RequestHandlerInterface
    {
        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->method('handle')->willReturn(new Response());
        return $handler;
    }

    private function createMiddlewareWithStorage(int $max = 60, int $window = 60): RateLimitMiddleware
    {
        $middleware = new RateLimitMiddleware($max, $window);
        // Override storage path via reflection
        $ref = new \ReflectionProperty(RateLimitMiddleware::class, 'storagePath');
        $ref->setAccessible(true);
        $ref->setValue($middleware, $this->storagePath);
        return $middleware;
    }

    public function testAllowsRequestUnderLimit(): void
    {
        $middleware = $this->createMiddlewareWithStorage(60, 60);
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.1']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals('60', $result->getHeaderLine('X-RateLimit-Limit'));
        $this->assertEquals('59', $result->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertNotEmpty($result->getHeaderLine('X-RateLimit-Reset'));
    }

    public function testRemainingDecrementsPerRequest(): void
    {
        $middleware = $this->createMiddlewareWithStorage(5, 60);
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.2']);
        $handler = $this->createHandler();

        $result1 = $middleware->process($request, $handler);
        $result2 = $middleware->process($request, $handler);
        $result3 = $middleware->process($request, $handler);

        $this->assertEquals('4', $result1->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertEquals('3', $result2->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertEquals('2', $result3->getHeaderLine('X-RateLimit-Remaining'));
    }

    public function testReturns429WhenLimitExceeded(): void
    {
        $middleware = $this->createMiddlewareWithStorage(2, 60);
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.3']);
        $handler = $this->createHandler();

        $middleware->process($request, $handler);
        $middleware->process($request, $handler);
        $result = $middleware->process($request, $handler);

        $body = $this->getResponseBody($result);

        $this->assertEquals(429, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertStringContainsString('Too many requests', $body['message']);
        $this->assertEquals('0', $result->getHeaderLine('X-RateLimit-Remaining'));
        $this->assertNotEmpty($result->getHeaderLine('Retry-After'));
    }

    public function testDifferentIpsTrackedSeparately(): void
    {
        $middleware = $this->createMiddlewareWithStorage(1, 60);
        $handler = $this->createHandler();

        $request1 = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.10']);
        $request2 = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.11']);

        $result1 = $middleware->process($request1, $handler);
        $result2 = $middleware->process($request2, $handler);

        $this->assertEquals(200, $result1->getStatusCode());
        $this->assertEquals(200, $result2->getStatusCode());
    }

    public function testExpiredRequestsAreCleaned(): void
    {
        $middleware = $this->createMiddlewareWithStorage(2, 1); // 1 second window
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '10.0.0.20']);
        $handler = $this->createHandler();

        $middleware->process($request, $handler);
        $middleware->process($request, $handler);

        // Wait for window to expire
        sleep(2);

        $result = $middleware->process($request, $handler);
        $this->assertEquals(200, $result->getStatusCode());
    }

    public function testHandlesInvalidIp(): void
    {
        $middleware = $this->createMiddlewareWithStorage(60, 60);
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => 'not-an-ip']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
    }

    public function testHandlesNoRemoteAddr(): void
    {
        $middleware = $this->createMiddlewareWithStorage(60, 60);
        $request = $this->createRequest('GET', '/', [], null, []);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
    }

    public function testHandlesCorruptedDataFile(): void
    {
        $middleware = $this->createMiddlewareWithStorage(60, 60);

        // Write corrupt data
        $key = md5('0.0.0.0');
        file_put_contents($this->storagePath . '/' . $key . '.json', 'not-json');

        $request = $this->createRequest('GET', '/', [], null, []);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals(200, $result->getStatusCode());
    }

    public function testDefaultConstructorValues(): void
    {
        $middleware = new RateLimitMiddleware();
        $request = $this->createRequest('GET', '/', [], null, ['REMOTE_ADDR' => '127.0.0.1']);
        $handler = $this->createHandler();

        $result = $middleware->process($request, $handler);

        $this->assertEquals('60', $result->getHeaderLine('X-RateLimit-Limit'));
    }

    public function testConstructorCreatesMissingStorageDir(): void
    {
        // Temporarily rename storage/rate_limit so the constructor triggers mkdir
        $basePath = defined('BASE_PATH') ? BASE_PATH : dirname(__DIR__, 2);
        $dir = $basePath . '/storage/rate_limit';
        $tmpName = $dir . '_bak_' . uniqid();
        $renamed = false;

        if (is_dir($dir)) {
            rename($dir, $tmpName);
            $renamed = true;
        }

        try {
            // Constructor will see !is_dir and call mkdir (line 30)
            new RateLimitMiddleware(60, 60);
            $this->assertDirectoryExists($dir);
        } finally {
            // Restore original dir
            if ($renamed) {
                if (is_dir($dir)) {
                    @rmdir($dir);
                }
                rename($tmpName, $dir);
            }
        }
    }
}

<?php

declare(strict_types=1);

namespace Tests\Handlers;

use App\Handlers\ErrorHandler;
use PHPUnit\Framework\TestCase;
use Slim\App;
use Slim\Exception\HttpNotFoundException;
use Slim\Exception\HttpMethodNotAllowedException;
use Slim\Exception\HttpForbiddenException;
use Slim\Psr7\Factory\ResponseFactory;
use Tests\TestHelper;

class ErrorHandlerTest extends TestCase
{
    use TestHelper;

    private ErrorHandler $handler;
    private App $app;

    protected function setUp(): void
    {
        $this->app = $this->createMock(App::class);
        $this->app->method('getResponseFactory')->willReturn(new ResponseFactory());

        $logger = $this->createMockLogger();
        $this->handler = new ErrorHandler($this->app, $logger);
    }

    public function testGenericExceptionReturns500(): void
    {
        $request = $this->createRequest('GET', '/broken');
        $exception = new \RuntimeException('Something broke');

        $result = ($this->handler)($request, $exception, false, true, false);
        $body = $this->getResponseBody($result);

        $this->assertEquals(500, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertEquals('Internal server error', $body['message']);
        $this->assertArrayNotHasKey('detail', $body);
        $this->assertArrayNotHasKey('trace', $body);
    }

    public function testNotFoundExceptionReturns404(): void
    {
        $request = $this->createRequest('GET', '/nonexistent');
        $exception = new HttpNotFoundException($request);

        $result = ($this->handler)($request, $exception, false, true, false);
        $body = $this->getResponseBody($result);

        $this->assertEquals(404, $result->getStatusCode());
        $this->assertEquals('Resource not found', $body['message']);
    }

    public function testMethodNotAllowedReturns405(): void
    {
        $request = $this->createRequest('PATCH', '/api/v1/users');
        $exception = new HttpMethodNotAllowedException($request);

        $result = ($this->handler)($request, $exception, false, true, false);
        $body = $this->getResponseBody($result);

        $this->assertEquals(405, $result->getStatusCode());
        $this->assertEquals('Method not allowed', $body['message']);
    }

    public function testHttpExceptionUsesItsCodeAndMessage(): void
    {
        $request = $this->createRequest('GET', '/forbidden');
        $exception = new HttpForbiddenException($request, 'Access denied');

        $result = ($this->handler)($request, $exception, false, true, false);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
        $this->assertEquals('Access denied', $body['message']);
    }

    public function testDisplayErrorDetailsExposesInfo(): void
    {
        $request = $this->createRequest('GET', '/broken');
        $exception = new \RuntimeException('Secret internal error');

        $result = ($this->handler)($request, $exception, true, true, false);
        $body = $this->getResponseBody($result);

        $this->assertEquals(500, $result->getStatusCode());
        $this->assertEquals('Internal server error', $body['message']);
        $this->assertArrayHasKey('detail', $body);
        $this->assertEquals('Secret internal error', $body['detail']);
        $this->assertArrayHasKey('trace', $body);
    }

    public function testNoLoggingWhenLogErrorsFalse(): void
    {
        $logger = $this->createMockLogger();
        $testHandler = $logger->getHandlers()[0];

        $handler = new ErrorHandler($this->app, $logger);
        $request = $this->createRequest('GET', '/broken');
        $exception = new \RuntimeException('Error');

        $handler($request, $exception, false, false, false);

        $this->assertEmpty($testHandler->getRecords());
    }

    public function testLogsErrorWhenLogErrorsTrue(): void
    {
        $logger = $this->createMockLogger();
        /** @var \Monolog\Handler\TestHandler $testHandler */
        $testHandler = $logger->getHandlers()[0];

        $handler = new ErrorHandler($this->app, $logger);
        $request = $this->createRequest('GET', '/broken', [], null, ['REMOTE_ADDR' => '10.0.0.1']);
        $exception = new \RuntimeException('Logged error');

        $handler($request, $exception, false, true, false);

        $this->assertTrue($testHandler->hasErrorRecords());
        $records = $testHandler->getRecords();
        $this->assertStringContainsString('Logged error', $records[0]['message']);
    }

    public function testLogsTraceWhenLogErrorDetailsTrue(): void
    {
        $logger = $this->createMockLogger();
        /** @var \Monolog\Handler\TestHandler $testHandler */
        $testHandler = $logger->getHandlers()[0];

        $handler = new ErrorHandler($this->app, $logger);
        $request = $this->createRequest('GET', '/broken');
        $exception = new \RuntimeException('Traced error');

        $handler($request, $exception, false, true, true);

        $records = $testHandler->getRecords();
        $this->assertArrayHasKey('trace', $records[0]['context']);
    }

    public function testResponseHasJsonContentType(): void
    {
        $request = $this->createRequest('GET', '/broken');
        $exception = new \RuntimeException('Error');

        $result = ($this->handler)($request, $exception, false, false, false);

        $this->assertEquals('application/json', $result->getHeaderLine('Content-Type'));
    }
}

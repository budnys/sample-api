<?php

declare(strict_types=1);

namespace Tests\Controllers;

use App\Controllers\HealthController;
use PHPUnit\Framework\TestCase;
use Tests\TestHelper;

class HealthControllerTest extends TestCase
{
    use TestHelper;

    private HealthController $controller;

    protected function setUp(): void
    {
        $this->controller = new HealthController();
    }

    public function testIndexReturnsJsonWithSuccessTrue(): void
    {
        $request = $this->createRequest('GET', '/health');
        $response = $this->createResponse();

        $result = $this->controller->index($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals('application/json', $result->getHeaderLine('Content-Type'));
        $this->assertTrue($body['success']);
        $this->assertEquals('API is running', $body['message']);
        $this->assertEquals('1.0.0', $body['version']);
        $this->assertEquals('/docs', $body['docs']);
        $this->assertArrayHasKey('timestamp', $body);
    }

    public function testDocsReturnsHtml(): void
    {
        $request = $this->createRequest('GET', '/docs');
        $response = $this->createResponse();

        $result = $this->controller->docs($request, $response);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals('text/html; charset=utf-8', $result->getHeaderLine('Content-Type'));

        $result->getBody()->rewind();
        $html = $result->getBody()->getContents();
        $this->assertStringContainsString('<!DOCTYPE html>', $html);
        $this->assertStringContainsString('GoNyva', $html);
        $this->assertStringContainsString('swagger-ui', $html);
    }
}

<?php

declare(strict_types=1);

namespace Tests;

use Slim\Psr7\Factory\StreamFactory;
use Slim\Psr7\Factory\UriFactory;
use Slim\Psr7\Headers;
use Slim\Psr7\Request;
use Slim\Psr7\Response;
use Slim\Psr7\Uri;

trait TestHelper
{
    protected function createRequest(
        string $method = 'GET',
        string $uri = '/',
        array $headers = [],
        ?array $body = null,
        array $serverParams = [],
        array $attributes = []
    ): Request {
        $uriObj = (new UriFactory())->createUri($uri);
        $stream = (new StreamFactory())->createStream();
        $h = new Headers();
        foreach ($headers as $name => $value) {
            $h->addHeader($name, $value);
        }

        if ($body !== null) {
            $stream->write(json_encode($body));
            $stream->rewind();
        }

        $request = new Request($method, $uriObj, $h, [], $serverParams, $stream);

        if ($body !== null) {
            $request = $request->withParsedBody($body);
        }

        foreach ($attributes as $key => $value) {
            $request = $request->withAttribute($key, $value);
        }

        return $request;
    }

    protected function createResponse(): Response
    {
        return new Response();
    }

    protected function getResponseBody(Response $response): array
    {
        $response->getBody()->rewind();
        return json_decode($response->getBody()->getContents(), true) ?? [];
    }

    protected function createMockLogger(): \Monolog\Logger
    {
        $logger = new \Monolog\Logger('test');
        $logger->pushHandler(new \Monolog\Handler\TestHandler());
        return $logger;
    }

    protected function createMockPdo(): \PDO
    {
        $pdo = $this->createMock(\PDO::class);
        return $pdo;
    }

    protected function createMockStatement(mixed $fetchReturn = false, int $rowCount = 0): \PDOStatement
    {
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn($fetchReturn);
        $stmt->method('fetchAll')->willReturn(is_array($fetchReturn) && !empty($fetchReturn) && isset($fetchReturn[0]) ? $fetchReturn : ($fetchReturn ? [$fetchReturn] : []));
        $stmt->method('fetchColumn')->willReturn($rowCount);
        $stmt->method('rowCount')->willReturn($rowCount);
        return $stmt;
    }
}

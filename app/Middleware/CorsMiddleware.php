<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Slim\Psr7\Response as SlimResponse;

/**
 * OWASP: CORS middleware to restrict cross-origin access
 */
class CorsMiddleware implements MiddlewareInterface
{
    private array $allowedOrigins;
    private string $allowedMethods;
    private string $allowedHeaders;
    private int $maxAge;

    public function __construct(array $settings)
    {
        $this->allowedOrigins = $settings['allowed_origins'] ?? [];
        $this->allowedMethods = $settings['allowed_methods'] ?? 'GET,POST,PUT,DELETE,OPTIONS';
        $this->allowedHeaders = $settings['allowed_headers'] ?? 'Content-Type,Authorization';
        $this->maxAge = $settings['max_age'] ?? 86400;
    }

    public function process(Request $request, Handler $handler): Response
    {
        $origin = $request->getHeaderLine('Origin');

        // Preflight request
        if ($request->getMethod() === 'OPTIONS') {
            $response = new SlimResponse();
            return $this->addCorsHeaders($response, $origin)->withStatus(204);
        }

        $response = $handler->handle($request);

        return $this->addCorsHeaders($response, $origin);
    }

    private function addCorsHeaders(Response $response, string $origin): Response
    {
        if (empty($origin) || !$this->isOriginAllowed($origin)) {
            return $response;
        }

        return $response
            ->withHeader('Access-Control-Allow-Origin', $origin)
            ->withHeader('Access-Control-Allow-Methods', $this->allowedMethods)
            ->withHeader('Access-Control-Allow-Headers', $this->allowedHeaders)
            ->withHeader('Access-Control-Max-Age', (string) $this->maxAge)
            ->withHeader('Access-Control-Allow-Credentials', 'true')
            ->withHeader('Vary', 'Origin');
    }

    private function isOriginAllowed(string $origin): bool
    {
        if (empty($this->allowedOrigins)) {
            return false;
        }

        if (in_array('*', $this->allowedOrigins, true)) {
            return true;
        }

        return in_array($origin, $this->allowedOrigins, true);
    }
}

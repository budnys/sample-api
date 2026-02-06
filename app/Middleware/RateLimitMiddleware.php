<?php

declare(strict_types=1);

namespace App\Middleware;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Slim\Psr7\Response as SlimResponse;

/**
 * OWASP A04: Insecure Design - Rate limiting to prevent abuse
 * Uses file-based storage suitable for shared hosting (no Redis required)
 */
class RateLimitMiddleware implements MiddlewareInterface
{
    private int $maxRequests;
    private int $windowSeconds;
    private string $storagePath;

    public function __construct(int $maxRequests = 60, int $windowSeconds = 60)
    {
        $this->maxRequests = $maxRequests;
        $this->windowSeconds = $windowSeconds;
        $this->storagePath = (defined('BASE_PATH') ? BASE_PATH : dirname(__DIR__, 2)) . '/storage/rate_limit';

        if (!is_dir($this->storagePath)) {
            mkdir($this->storagePath, 0750, true);
        }
    }

    public function process(Request $request, Handler $handler): Response
    {
        $clientIp = $this->getClientIp($request);
        $key = md5($clientIp);
        $file = $this->storagePath . '/' . $key . '.json';
        $now = time();

        $data = $this->loadData($file);

        // Clean expired entries
        $data['requests'] = array_filter(
            $data['requests'] ?? [],
            fn(int $timestamp) => $timestamp > ($now - $this->windowSeconds)
        );

        $remaining = $this->maxRequests - count($data['requests']);

        if ($remaining <= 0) {
            $oldestRequest = min($data['requests']);
            $retryAfter = $oldestRequest + $this->windowSeconds - $now;

            $response = new SlimResponse();
            $response->getBody()->write(json_encode([
                'success' => false,
                'message' => 'Too many requests. Please try again later.',
            ]));

            return $response
                ->withStatus(429)
                ->withHeader('Content-Type', 'application/json')
                ->withHeader('Retry-After', (string) max(1, $retryAfter))
                ->withHeader('X-RateLimit-Limit', (string) $this->maxRequests)
                ->withHeader('X-RateLimit-Remaining', '0')
                ->withHeader('X-RateLimit-Reset', (string) ($oldestRequest + $this->windowSeconds));
        }

        // Record this request
        $data['requests'][] = $now;
        $this->saveData($file, $data);

        $response = $handler->handle($request);

        return $response
            ->withHeader('X-RateLimit-Limit', (string) $this->maxRequests)
            ->withHeader('X-RateLimit-Remaining', (string) ($remaining - 1))
            ->withHeader('X-RateLimit-Reset', (string) ($now + $this->windowSeconds));
    }

    private function getClientIp(Request $request): string
    {
        $serverParams = $request->getServerParams();
        $ip = $serverParams['REMOTE_ADDR'] ?? '0.0.0.0';
        return filter_var($ip, FILTER_VALIDATE_IP) ?: '0.0.0.0';
    }

    private function loadData(string $file): array
    {
        if (!file_exists($file)) {
            return ['requests' => []];
        }

        $content = file_get_contents($file);
        $data = json_decode($content, true);

        return is_array($data) ? $data : ['requests' => []];
    }

    private function saveData(string $file, array $data): void
    {
        file_put_contents($file, json_encode($data), LOCK_EX);
    }
}

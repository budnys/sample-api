<?php

declare(strict_types=1);

namespace App\Middleware;

use App\Services\JwtService;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface as Handler;
use Slim\Psr7\Response as SlimResponse;

/**
 * OWASP A01: Broken Access Control - JWT authentication middleware
 * OWASP A07: Identification and Authentication Failures
 */
class JwtMiddleware implements MiddlewareInterface
{
    private JwtService $jwt;

    public function __construct(JwtService $jwt)
    {
        $this->jwt = $jwt;
    }

    public function process(Request $request, Handler $handler): Response
    {
        $authHeader = $request->getHeaderLine('Authorization');

        if (empty($authHeader) || !preg_match('/^Bearer\s+(.+)$/i', $authHeader, $matches)) {
            return $this->unauthorizedResponse('Missing or invalid Authorization header.');
        }

        $token = $matches[1];

        try {
            $payload = $this->jwt->decode($token);
        } catch (\Exception $e) {
            return $this->unauthorizedResponse('Invalid or expired token.');
        }

        // Attach decoded user data to request for downstream use
        $request = $request->withAttribute('jwt_payload', $payload);
        $request = $request->withAttribute('user_id', $payload->sub ?? null);

        return $handler->handle($request);
    }

    private function unauthorizedResponse(string $message): Response
    {
        $response = new SlimResponse();
        $response->getBody()->write(json_encode([
            'success' => false,
            'message' => $message,
        ]));

        return $response
            ->withStatus(401)
            ->withHeader('Content-Type', 'application/json')
            ->withHeader('WWW-Authenticate', 'Bearer');
    }
}

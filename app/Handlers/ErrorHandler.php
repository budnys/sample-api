<?php

declare(strict_types=1);

namespace App\Handlers;

use Monolog\Logger;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Slim\App;
use Slim\Exception\HttpException;
use Slim\Exception\HttpNotFoundException;
use Slim\Exception\HttpMethodNotAllowedException;
use Slim\Interfaces\ErrorHandlerInterface;
use Throwable;

/**
 * OWASP A05: Security Misconfiguration - Never expose stack traces or internals
 * OWASP A09: Security Logging - Log all errors for monitoring
 */
class ErrorHandler implements ErrorHandlerInterface
{
    private App $app;
    private Logger $logger;

    public function __construct(App $app, Logger $logger)
    {
        $this->app = $app;
        $this->logger = $logger;
    }

    public function __invoke(
        Request $request,
        Throwable $exception,
        bool $displayErrorDetails,
        bool $logErrors,
        bool $logErrorDetails
    ): Response {
        // OWASP A09: Log the error with context
        if ($logErrors) {
            $context = [
                'method' => $request->getMethod(),
                'uri' => (string) $request->getUri(),
                'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? 'unknown',
            ];

            if ($logErrorDetails) {
                $context['trace'] = $exception->getTraceAsString();
            }

            $this->logger->error($exception->getMessage(), $context);
        }

        // Determine status code
        $statusCode = 500;
        $message = 'Internal server error';

        if ($exception instanceof HttpNotFoundException) {
            $statusCode = 404;
            $message = 'Resource not found';
        } elseif ($exception instanceof HttpMethodNotAllowedException) {
            $statusCode = 405;
            $message = 'Method not allowed';
        } elseif ($exception instanceof HttpException) {
            $statusCode = $exception->getCode();
            $message = $exception->getMessage();
        }

        // OWASP A05: Build safe response - never expose internals in production
        $error = [
            'success' => false,
            'message' => $message,
        ];

        if ($displayErrorDetails) {
            $error['detail'] = $exception->getMessage();
            $error['trace'] = $exception->getTraceAsString();
        }

        $response = $this->app->getResponseFactory()->createResponse($statusCode);
        $response->getBody()->write(json_encode($error, JSON_UNESCAPED_UNICODE));

        return $response->withHeader('Content-Type', 'application/json');
    }
}

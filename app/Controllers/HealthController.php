<?php

declare(strict_types=1);

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

class HealthController
{
    public function index(Request $request, Response $response): Response
    {
        $data = [
            'success' => true,
            'message' => 'API is running',
            'timestamp' => date('c'),
            'version' => '1.0.0',
            'docs' => '/docs',
        ];

        $response->getBody()->write(json_encode($data));
        return $response->withHeader('Content-Type', 'application/json');
    }

    /**
     * GET /docs — Swagger UI documentation page
     */
    public function docs(Request $request, Response $response): Response
    {
        $html = file_get_contents(BASE_PATH . '/public/docs/index.html');
        $response->getBody()->write($html);
        return $response->withHeader('Content-Type', 'text/html; charset=utf-8');
    }

}

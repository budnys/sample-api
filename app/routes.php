<?php

declare(strict_types=1);

use Slim\App;
use Slim\Routing\RouteCollectorProxy;
use App\Controllers\AuthController;
use App\Controllers\UserController;
use App\Controllers\HealthController;
use App\Controllers\ContactController;
use App\Controllers\EmailController;
use App\Middleware\JwtMiddleware;

/**
 * API Route Definitions
 */
return function (App $app) {
    // Health check (public)
    $app->get('/', [HealthController::class, 'index']);
    $app->get('/health', [HealthController::class, 'index']);

    // Swagger docs (public)
    $app->get('/docs', [HealthController::class, 'docs']);

    // API v1 routes
    $app->group('/api/v1', function (RouteCollectorProxy $group) {

        // Public auth routes
        $group->post('/auth/register', [AuthController::class, 'register']);
        $group->post('/auth/login', [AuthController::class, 'login']);
        $group->post('/auth/refresh', [AuthController::class, 'refresh']);

        // Public contact form (protected by hCaptcha, not JWT)
        $group->post('/contact', [ContactController::class, 'submit']);

        // Protected routes (require JWT)
        $group->group('', function (RouteCollectorProxy $protected) {
            $protected->get('/auth/me', [AuthController::class, 'me']);
            $protected->post('/auth/logout', [AuthController::class, 'logout']);

            // Users resource
            $protected->get('/users', [UserController::class, 'list']);
            $protected->get('/users/{id}', [UserController::class, 'show']);
            $protected->put('/users/{id}', [UserController::class, 'update']);
            $protected->delete('/users/{id}', [UserController::class, 'delete']);

            // Email
            $protected->post('/email/send', [EmailController::class, 'send']);
        })->add(JwtMiddleware::class);
    });
};

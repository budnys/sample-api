<?php

declare(strict_types=1);

use Slim\App;
use App\Middleware\CorsMiddleware;
use App\Middleware\RateLimitMiddleware;
use App\Middleware\SecurityHeadersMiddleware;

/**
 * Register global middleware
 * OWASP: Middleware is executed in LIFO order (last added = first executed)
 */
return function (App $app) {
    $container = $app->getContainer();
    $settings = $container->get('settings');

    // Security Headers (runs on every response)
    $app->add(new SecurityHeadersMiddleware());

    // CORS (OWASP: restrict cross-origin access)
    $app->add(new CorsMiddleware($settings['cors']));

    // Rate Limiting (OWASP A04: protect against abuse)
    $app->add(new RateLimitMiddleware(
        $settings['rate_limit']['max_requests'],
        $settings['rate_limit']['window_seconds']
    ));
};

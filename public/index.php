<?php

declare(strict_types=1);

/**
 * Secure API Entry Point
 * OWASP: Front controller pattern - single entry point for all requests
 */

// OWASP A05: Suppress PHP version exposure and error display
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('expose_php', '0');
error_reporting(E_ALL);

define('BASE_PATH', dirname(__DIR__));

require BASE_PATH . '/vendor/autoload.php';

// Load environment variables
$dotenv = Dotenv\Dotenv::createImmutable(BASE_PATH);
$dotenv->safeLoad();

// Bootstrap application
$app = require BASE_PATH . '/app/bootstrap.php';

$app->run();

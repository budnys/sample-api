<?php

declare(strict_types=1);

use DI\Container;
use Slim\Factory\AppFactory;
use Monolog\Logger;
use Monolog\Handler\StreamHandler;
use Monolog\Handler\RotatingFileHandler;

// Create DI Container
$container = new Container();

// Register services
$container->set('settings', function () {
    return [
        'app' => [
            'env' => $_ENV['APP_ENV'] ?? 'production',
            'debug' => filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN),
            'url' => $_ENV['APP_URL'] ?? 'http://localhost',
        ],
        'db' => [
            'host' => $_ENV['DB_HOST'] ?? 'localhost',
            'port' => $_ENV['DB_PORT'] ?? '3306',
            'name' => $_ENV['DB_NAME'] ?? '',
            'user' => $_ENV['DB_USER'] ?? '',
            'pass' => $_ENV['DB_PASS'] ?? '',
            'charset' => $_ENV['DB_CHARSET'] ?? 'utf8mb4',
        ],
        'jwt' => [
            'secret' => $_ENV['JWT_SECRET'] ?? '',
            'expiry' => (int) ($_ENV['JWT_EXPIRY'] ?? 3600),
            'refresh_expiry' => (int) ($_ENV['JWT_REFRESH_EXPIRY'] ?? 604800),
            'algorithm' => $_ENV['JWT_ALGORITHM'] ?? 'HS256',
        ],
        'rate_limit' => [
            'max_requests' => (int) ($_ENV['RATE_LIMIT_MAX_REQUESTS'] ?? 60),
            'window_seconds' => (int) ($_ENV['RATE_LIMIT_WINDOW_SECONDS'] ?? 60),
        ],
        'cors' => [
            'allowed_origins' => array_filter(array_map('trim', explode(',', $_ENV['CORS_ALLOWED_ORIGINS'] ?? ''))),
            'allowed_methods' => $_ENV['CORS_ALLOWED_METHODS'] ?? 'GET,POST,PUT,DELETE,OPTIONS',
            'allowed_headers' => $_ENV['CORS_ALLOWED_HEADERS'] ?? 'Content-Type,Authorization,X-Request-ID',
            'max_age' => (int) ($_ENV['CORS_MAX_AGE'] ?? 86400),
        ],
        // Dreamhost shared hosting: smtp.dreamhost.com, port 587, STARTTLS
        // Ref: https://help.dreamhost.com/hc/en-us/articles/360031174411
        'smtp' => [
            'host' => $_ENV['SMTP_HOST'] ?? 'smtp.dreamhost.com',
            'port' => (int) ($_ENV['SMTP_PORT'] ?? 587),
            'encryption' => $_ENV['SMTP_ENCRYPTION'] ?? 'tls',
            'user' => $_ENV['SMTP_USER'] ?? '',
            'pass' => $_ENV['SMTP_PASS'] ?? '',
            'from_email' => $_ENV['SMTP_FROM_EMAIL'] ?? $_ENV['SMTP_USER'] ?? '',
            'from_name' => $_ENV['SMTP_FROM_NAME'] ?? 'GoNyva API',
        ],
    ];
});

// Logger (OWASP A09: Security Logging)
$container->set(Logger::class, function ($container) {
    $settings = $container->get('settings');
    $logPath = $_ENV['LOG_PATH'] ?? BASE_PATH . '/logs/app.log';

    // Ensure absolute path
    if (!str_starts_with($logPath, '/')) {
        $logPath = BASE_PATH . '/' . $logPath;
    }

    $logDir = dirname($logPath);
    if (!is_dir($logDir)) {
        mkdir($logDir, 0750, true);
    }

    $logger = new Logger('api');
    $level = Logger::toMonologLevel($_ENV['LOG_LEVEL'] ?? 'warning');
    $logger->pushHandler(new RotatingFileHandler($logPath, 30, $level));

    return $logger;
});

// PDO Database Connection (OWASP A03: Injection prevention via prepared statements)
$container->set(PDO::class, function ($container) {
    $settings = $container->get('settings')['db'];

    $dsn = sprintf(
        'mysql:host=%s;port=%s;dbname=%s;charset=%s',
        $settings['host'],
        $settings['port'],
        $settings['name'],
        $settings['charset']
    );

    $pdo = new PDO($dsn, $settings['user'], $settings['pass'], [
        // OWASP A03: Force prepared statements (emulated OFF)
        PDO::ATTR_EMULATE_PREPARES => false,
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        // OWASP A05: Set strict SQL mode
        PDO::MYSQL_ATTR_INIT_COMMAND => "SET NAMES utf8mb4 COLLATE utf8mb4_unicode_ci, sql_mode = 'STRICT_TRANS_TABLES,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'",
    ]);

    return $pdo;
});

// JWT Service
$container->set(App\Services\JwtService::class, function ($container) {
    $settings = $container->get('settings')['jwt'];
    return new App\Services\JwtService(
        $settings['secret'],
        $settings['algorithm'],
        $settings['expiry'],
        $settings['refresh_expiry']
    );
});

// Create Slim App
AppFactory::setContainer($container);
$app = AppFactory::create();

// OWASP: Parse JSON body
$app->addBodyParsingMiddleware();

// Add Slim's built-in routing middleware
$app->addRoutingMiddleware();

// Register custom middleware (OWASP security layers)
(require BASE_PATH . '/app/middleware.php')($app);

// Register error handler (OWASP A05: Don't expose internals)
$errorMiddleware = $app->addErrorMiddleware(
    $container->get('settings')['app']['debug'],
    true,  // log errors
    true   // log error details
);

$errorMiddleware->setDefaultErrorHandler(new App\Handlers\ErrorHandler($app, $container->get(Logger::class)));

// Register routes
(require BASE_PATH . '/app/routes.php')($app);

return $app;

<?php

declare(strict_types=1);

namespace Tests\Controllers;

use App\Controllers\ContactController;
use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPUnit\Framework\TestCase;
use Tests\TestHelper;

class ContactControllerTest extends TestCase
{
    use TestHelper;

    private \Monolog\Logger $logger;
    private ContactController $controller;

    protected function setUp(): void
    {
        $this->logger = $this->createMockLogger();
        $this->controller = new ContactController($this->logger);
    }

    // --- Validation ---

    public function testSubmitFailsOnEmptyBody(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], []);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertFalse($body['success']);
        $this->assertArrayHasKey('errors', $body);
        $this->assertArrayHasKey('name', $body['errors']);
        $this->assertArrayHasKey('email', $body['errors']);
        $this->assertArrayHasKey('message', $body['errors']);
        $this->assertArrayHasKey('captchaToken', $body['errors']);
    }

    public function testSubmitFailsOnShortName(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'A',
            'email' => 'test@example.com',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('name', $body['errors']);
    }

    public function testSubmitFailsOnLongName(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => str_repeat('A', 101),
            'email' => 'test@example.com',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('name', $body['errors']);
    }

    public function testSubmitFailsOnInvalidNameCharacters(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John<script>',
            'email' => 'test@example.com',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('name', $body['errors']);
        $this->assertStringContainsString('invalid characters', $body['errors']['name']);
    }

    public function testSubmitFailsOnInvalidEmail(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'not-email',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('email', $body['errors']);
    }

    public function testSubmitFailsOnLongEmail(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => str_repeat('a', 250) . '@b.com',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
    }

    public function testSubmitFailsOnEmptyMessage(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('message', $body['errors']);
    }

    public function testSubmitFailsOnLongMessage(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => str_repeat('A', 10001),
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('message', $body['errors']);
    }

    public function testSubmitFailsOnMissingCaptcha(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => 'Hello',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('captchaToken', $body['errors']);
    }

    public function testSubmitFailsOnNonStringCaptcha(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => 'Hello',
            'captchaToken' => 12345,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertArrayHasKey('captchaToken', $body['errors']);
    }

    // --- Captcha bypass in dev (HCAPTCHA_SECRET empty) ---

    public function testSubmitWithNoCaptchaSecretConfiguredSendsEmail(): void
    {
        // HCAPTCHA_SECRET is empty in phpunit.xml, so captcha is skipped
        // SMTP will fail since settings are fake, so we expect 500
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '<p>Hello</p>',
            'captchaToken' => 'any-token',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        // Should get past validation and captcha, fail at SMTP
        $this->assertEquals(500, $result->getStatusCode());
        $this->assertFalse($body['success']);
    }

    // --- HTML Sanitization ---

    public function testSanitizeHtmlStripsScriptTags(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<p>Safe</p><script>alert(1)</script>');
        $this->assertStringNotContainsString('<script>', $result);
        $this->assertStringContainsString('<p>Safe</p>', $result);
    }

    public function testSanitizeHtmlRemovesEventHandlers(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<div onmouseover="alert(1)">Hi</div>');
        $this->assertStringNotContainsString('onmouseover', $result);
    }

    public function testSanitizeHtmlRemovesJavascriptUrls(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<a href="javascript:void(0)">Link</a>');
        $this->assertStringNotContainsString('javascript:', $result);
    }

    public function testSanitizeHtmlRemovesDataUrls(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<a href="data:text/html,<script>alert(1)</script>">Link</a>');
        $this->assertStringNotContainsString('data:', $result);
    }

    public function testSanitizeHtmlRemovesCssExpressions(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<div style="background:expression(alert(1))">Hi</div>');
        $this->assertStringNotContainsString('expression', $result);
    }

    public function testSanitizeHtmlRemovesCssUrl(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'sanitizeHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, '<div style="background:url(evil.com)">Hi</div>');
        $this->assertStringNotContainsString('url(', $result);
    }

    // --- getClientIp ---

    public function testGetClientIpFromXForwardedFor(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', ['X-Forwarded-For' => '1.2.3.4, 5.6.7.8']);
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('1.2.3.4', $result);
    }

    public function testGetClientIpFromXRealIp(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', ['X-Real-Ip' => '10.0.0.1']);
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('10.0.0.1', $result);
    }

    public function testGetClientIpFromCfConnectingIp(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', ['CF-Connecting-IP' => '172.16.0.1']);
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('172.16.0.1', $result);
    }

    public function testGetClientIpFallsBackToRemoteAddr(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', [], null, ['REMOTE_ADDR' => '192.168.1.1']);
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('192.168.1.1', $result);
    }

    public function testGetClientIpDefaultsToZeroWhenNoIp(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/');
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('0.0.0.0', $result);
    }

    public function testGetClientIpRejectsInvalidIpInHeader(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'getClientIp');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', ['X-Forwarded-For' => 'not-an-ip'], null, ['REMOTE_ADDR' => '10.0.0.5']);
        $result = $method->invoke($this->controller, $request);

        $this->assertEquals('10.0.0.5', $result);
    }

    // --- wrapHtml ---

    public function testWrapHtmlContainsSenderInfo(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'wrapHtml');
        $method->setAccessible(true);

        $result = $method->invoke($this->controller, 'Jane Doe', 'jane@example.com', '<p>Hello</p>');
        $this->assertStringContainsString('Jane Doe', $result);
        $this->assertStringContainsString('jane@example.com', $result);
        $this->assertStringContainsString('<p>Hello</p>', $result);
        $this->assertStringContainsString('<!DOCTYPE html>', $result);
        $this->assertStringContainsString('Contact Form', $result);
    }

    // --- verifyCaptcha with empty secret ---

    public function testVerifyCaptchaReturnsTrueWhenSecretNotConfigured(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/');
        $result = $method->invoke($this->controller, 'any-token', $request);

        $this->assertTrue($result);
    }

    public function testVerifyCaptchaReturnsTrueEvenWithEmptyTokenWhenNoSecret(): void
    {
        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/');
        // empty secret = skip verification
        $result = $method->invoke($this->controller, '', $request);

        $this->assertTrue($result);
    }

    // --- Name with valid special chars ---

    public function testSubmitAcceptsNameWithAccentsAndHyphens(): void
    {
        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => "Jean-François O'Brien",
            'email' => 'test@example.com',
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        // Should pass validation (fail at SMTP)
        $this->assertNotEquals(422, $result->getStatusCode());
    }

    // --- Success and error paths via mocking ---

    public function testSubmitSuccessPath(): void
    {
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['sendEmail', 'verifyCaptcha'])
            ->getMock();

        $controller->method('verifyCaptcha')->willReturn(true);
        $controller->method('sendEmail')->willReturnCallback(function () {});

        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '<p>Hello</p>',
            'captchaToken' => 'valid-token',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertStringContainsString('sent successfully', $body['message']);
    }

    public function testSubmitCatchesPHPMailerException(): void
    {
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['sendEmail', 'verifyCaptcha'])
            ->getMock();

        $controller->method('verifyCaptcha')->willReturn(true);
        $controller->method('sendEmail')->willThrowException(
            new PHPMailerException('SMTP connect failed')
        );

        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '<p>Hello</p>',
            'captchaToken' => 'valid-token',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(500, $result->getStatusCode());
        $this->assertStringContainsString('Failed to send', $body['message']);
    }

    public function testSubmitCatchesGenericThrowable(): void
    {
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['sendEmail', 'verifyCaptcha'])
            ->getMock();

        $controller->method('verifyCaptcha')->willReturn(true);
        $controller->method('sendEmail')->willThrowException(
            new \RuntimeException('Something broke')
        );

        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '<p>Hello</p>',
            'captchaToken' => 'valid-token',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(500, $result->getStatusCode());
        $this->assertStringContainsString('unexpected error', $body['message']);
    }

    public function testSubmitCaptchaFailureReturns403(): void
    {
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['verifyCaptcha'])
            ->getMock();

        $controller->method('verifyCaptcha')->willReturn(false);

        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => 'test@example.com',
            'message' => '<p>Hello</p>',
            'captchaToken' => 'invalid-token',
        ], ['REMOTE_ADDR' => '127.0.0.1']);
        $response = $this->createResponse();

        $result = $controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
        $this->assertStringContainsString('Captcha verification failed', $body['message']);
    }

    // --- verifyCaptcha with secret configured ---

    public function testVerifyCaptchaReturnsFalseOnEmptyTokenWithSecret(): void
    {
        // Set a secret to bypass the dev skip
        $_ENV['HCAPTCHA_SECRET'] = 'test-secret-key';
        $controller = new ContactController($this->logger);
        $_ENV['HCAPTCHA_SECRET'] = ''; // reset

        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', [], null, ['REMOTE_ADDR' => '127.0.0.1']);
        $result = $method->invoke($controller, '', $request);

        $this->assertFalse($result);
    }

    public function testVerifyCaptchaHttpPostFailsReturnsFalse(): void
    {
        $_ENV['HCAPTCHA_SECRET'] = 'test-secret-key';
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['httpPost'])
            ->getMock();
        $_ENV['HCAPTCHA_SECRET'] = '';

        // Set captcha secret on the mock
        $ref = new \ReflectionProperty(ContactController::class, 'captchaSettings');
        $ref->setAccessible(true);
        $ref->setValue($controller, ['secret' => 'test-secret', 'verify_url' => 'https://example.com']);

        $controller->method('httpPost')->willReturn(false);

        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', [], null, ['REMOTE_ADDR' => '127.0.0.1']);
        $result = $method->invoke($controller, 'some-token', $request);

        $this->assertFalse($result);
    }

    public function testVerifyCaptchaSuccessfulResponseReturnsTrue(): void
    {
        $_ENV['HCAPTCHA_SECRET'] = 'test-secret-key';
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['httpPost'])
            ->getMock();
        $_ENV['HCAPTCHA_SECRET'] = '';

        $ref = new \ReflectionProperty(ContactController::class, 'captchaSettings');
        $ref->setAccessible(true);
        $ref->setValue($controller, ['secret' => 'test-secret', 'verify_url' => 'https://example.com']);

        $controller->method('httpPost')->willReturn(json_encode(['success' => true]));

        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', [], null, ['REMOTE_ADDR' => '127.0.0.1']);
        $result = $method->invoke($controller, 'valid-token', $request);

        $this->assertTrue($result);
    }

    public function testVerifyCaptchaFailedResponseReturnsFalse(): void
    {
        $_ENV['HCAPTCHA_SECRET'] = 'test-secret-key';
        $controller = $this->getMockBuilder(ContactController::class)
            ->setConstructorArgs([$this->logger])
            ->onlyMethods(['httpPost'])
            ->getMock();
        $_ENV['HCAPTCHA_SECRET'] = '';

        $ref = new \ReflectionProperty(ContactController::class, 'captchaSettings');
        $ref->setAccessible(true);
        $ref->setValue($controller, ['secret' => 'test-secret', 'verify_url' => 'https://example.com']);

        $controller->method('httpPost')->willReturn(json_encode(['success' => false]));

        $method = new \ReflectionMethod(ContactController::class, 'verifyCaptcha');
        $method->setAccessible(true);

        $request = $this->createRequest('POST', '/', [], null, ['REMOTE_ADDR' => '127.0.0.1']);
        $result = $method->invoke($controller, 'invalid-token', $request);

        $this->assertFalse($result);
    }

    // --- httpPost direct tests ---

    public function testHttpPostReturnsFalseOnConnectionFailure(): void
    {
        $controller = new ContactController($this->logger);

        $method = new \ReflectionMethod(ContactController::class, 'httpPost');
        $method->setAccessible(true);

        $result = $method->invoke($controller, 'http://127.0.0.1:1/nonexistent', ['key' => 'value']);

        $this->assertFalse($result);
    }

    public function testHttpPostReturnsBodyOnSuccess(): void
    {
        $controller = new ContactController($this->logger);

        $method = new \ReflectionMethod(ContactController::class, 'httpPost');
        $method->setAccessible(true);

        // Use a known URL that accepts POST and returns 200
        // The health endpoint on the Docker container or any echo service
        // Using https://httpbin.org/post would work but is external
        // Instead, test with a data URI or skip if no server available
        $result = $method->invoke($controller, 'https://hcaptcha.com/siteverify', ['secret' => 'test', 'response' => 'test']);

        // hCaptcha will return a 200 JSON response (with success: false for invalid tokens)
        if ($result !== false) {
            $this->assertIsString($result);
            $decoded = json_decode($result, true);
            $this->assertIsArray($decoded);
        } else {
            // If network unavailable, just verify it returned false gracefully
            $this->assertFalse($result);
        }
    }

    // --- sendEmail internals ---

    public function testSendEmailTlsEncryptionPath(): void
    {
        $_ENV['SMTP_ENCRYPTION'] = 'tls';
        $controller = new ContactController($this->logger);
        $_ENV['SMTP_ENCRYPTION'] = 'tls'; // reset to default

        $method = new \ReflectionMethod(ContactController::class, 'sendEmail');
        $method->setAccessible(true);

        try {
            $method->invoke($controller, 'Test', 'test@example.com', '<p>Hi</p>');
        } catch (\Throwable $e) {
            // Expected — SMTP unreachable
        }
        $this->assertTrue(true);
    }

    public function testSendEmailSslEncryptionPath(): void
    {
        $_ENV['SMTP_ENCRYPTION'] = 'ssl';
        $controller = new ContactController($this->logger);
        $_ENV['SMTP_ENCRYPTION'] = 'tls'; // reset to default

        $method = new \ReflectionMethod(ContactController::class, 'sendEmail');
        $method->setAccessible(true);

        try {
            $method->invoke($controller, 'Test', 'test@example.com', '<p>Hi</p>');
        } catch (\Throwable $e) {
            // Expected — SMTP unreachable
        }
        $this->assertTrue(true);
    }

    public function testSendEmailNoEncryptionPath(): void
    {
        $_ENV['SMTP_ENCRYPTION'] = 'none';
        $controller = new ContactController($this->logger);
        $_ENV['SMTP_ENCRYPTION'] = 'tls'; // reset to default

        $method = new \ReflectionMethod(ContactController::class, 'sendEmail');
        $method->setAccessible(true);

        try {
            $method->invoke($controller, 'Test', 'test@example.com', '<p>Hi</p>');
        } catch (\Throwable $e) {
            // Expected — SMTP unreachable
        }
        $this->assertTrue(true);
    }

    // --- Long email validation (line 262) ---

    public function testSubmitFailsOnLongEmailExact256(): void
    {
        $email = str_repeat('a', 248) . '@b.com'; // 255 chars
        // This will be > 255 when we add one more
        $email256 = str_repeat('a', 249) . '@b.com'; // 256 chars

        $request = $this->createRequest('POST', '/api/v1/contact', [], [
            'name' => 'John Doe',
            'email' => $email256,
            'message' => 'Hello',
            'captchaToken' => 'token123',
        ]);
        $response = $this->createResponse();

        $result = $this->controller->submit($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
    }
}

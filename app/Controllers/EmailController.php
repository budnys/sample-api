<?php

declare(strict_types=1);

namespace App\Controllers;

use Monolog\Logger;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception as PHPMailerException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Email sending controller using Dreamhost SMTP
 * Ref: https://help.dreamhost.com/hc/en-us/articles/360031174411
 * OWASP A03: Input validation and sanitization for email content
 * OWASP A07: JWT-protected endpoint
 */
class EmailController
{
    private array $smtpSettings;
    private Logger $logger;

    public function __construct(Logger $logger)
    {
        $this->logger = $logger;
        $this->smtpSettings = [
            // Dreamhost shared hosting: use smtp.dreamhost.com, port 587, STARTTLS
            // Ref: https://help.dreamhost.com/hc/en-us/articles/360031174411
            'host' => $_ENV['SMTP_HOST'] ?? 'smtp.dreamhost.com',
            'port' => (int) ($_ENV['SMTP_PORT'] ?? 587),
            'encryption' => $_ENV['SMTP_ENCRYPTION'] ?? 'tls',
            'user' => $_ENV['SMTP_USER'] ?? '',
            'pass' => $_ENV['SMTP_PASS'] ?? '',
            // Dreamhost requires setFrom to match the SMTP username
            'from_email' => $_ENV['SMTP_FROM_EMAIL'] ?? $_ENV['SMTP_USER'] ?? '',
            'from_name' => $_ENV['SMTP_FROM_NAME'] ?? 'GoNyva API',
            'debug' => filter_var($_ENV['APP_DEBUG'] ?? false, FILTER_VALIDATE_BOOLEAN),
            'timeout' => (int) ($_ENV['SMTP_TIMEOUT'] ?? 30),
        ];
    }

    /**
     * POST /api/v1/email/send
     *
     * Request body:
     * {
     *   "name": "Sender Name",
     *   "email": "recipient@example.com",
     *   "message": "<p>HTML content here</p>"
     * }
     *
     * Responses:
     *   200 - Email sent successfully
     *   401 - Unauthorized (missing/invalid JWT)
     *   403 - Forbidden
     *   422 - Validation error
     *   500 - SMTP / server error
     */
    public function send(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();
        $userId = $request->getAttribute('user_id');

        // Validate input
        $errors = $this->validateInput($body);
        if (!empty($errors)) {
            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $errors,
            ], 422);
        }

        $name = trim($body['name']);
        $recipientEmail = strtolower(trim($body['email']));
        $htmlMessage = $body['message'];

        // OWASP A03: Sanitize the name field (but allow HTML in message as requested)
        $name = htmlspecialchars($name, ENT_QUOTES | ENT_HTML5, 'UTF-8');

        // Purify HTML message — strip dangerous tags/attributes
        $htmlMessage = $this->sanitizeHtml($htmlMessage);

        try {
            $this->sendEmail($name, $recipientEmail, $htmlMessage);

            $this->logger->info('Email sent successfully', [
                'to' => $recipientEmail,
                'from_name' => $name,
                'user_id' => $userId,
            ]);

            return $this->jsonResponse($response, [
                'success' => true,
                'message' => 'Email sent successfully',
            ], 200);
        } catch (PHPMailerException $e) {
            $this->logger->error('SMTP error sending email', [
                'error' => $e->getMessage(),
                'to' => $recipientEmail,
                'user_id' => $userId,
            ]);

            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Failed to send email. Please try again later.',
            ], 500);
        } catch (\Throwable $e) {
            $this->logger->critical('Unexpected error sending email', [
                'error' => $e->getMessage(),
                'user_id' => $userId,
            ]);

            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Internal server error',
            ], 500);
        }
    }

    protected function sendEmail(string $senderName, string $recipientEmail, string $htmlMessage): void
    {
        $mail = new PHPMailer(true);

        // Dreamhost shared hosting PHPMailer configuration
        // Ref: https://help.dreamhost.com/hc/en-us/articles/360031174411
        $mail->SMTPDebug = $this->smtpSettings['debug'] ? SMTP::DEBUG_SERVER : SMTP::DEBUG_OFF;
        $mail->isSMTP();
        $mail->Host = $this->smtpSettings['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $this->smtpSettings['user'];
        $mail->Password = $this->smtpSettings['pass'];

        // Dreamhost recommends STARTTLS on port 587
        $encryption = strtolower($this->smtpSettings['encryption']);
        if ($encryption === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
            $mail->Port = $this->smtpSettings['port'] ?: 587;
        } elseif ($encryption === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
            $mail->Port = $this->smtpSettings['port'] ?: 465;
        } else {
            $mail->SMTPSecure = false;
            $mail->Port = $this->smtpSettings['port'] ?: 587;
        }

        // Sender and recipient
        $mail->setFrom($this->smtpSettings['from_email'], $this->smtpSettings['from_name']);
        $mail->addReplyTo($this->smtpSettings['from_email'], $senderName);
        $mail->addAddress($recipientEmail);

        // Email content
        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';
        $mail->Subject = "Message from {$senderName} via GoNyva";
        $mail->Body = $this->wrapHtml($senderName, $htmlMessage);
        $mail->AltBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlMessage));

        // Timeout settings for shared hosting
        $mail->Timeout = $this->smtpSettings['timeout'];
        $mail->SMTPKeepAlive = false;

        $mail->send();
    }

    private function wrapHtml(string $senderName, string $htmlContent): string
    {
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5;">
    <div style="max-width: 600px; margin: 0 auto; background-color: #ffffff; border-radius: 8px; padding: 30px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
        <h2 style="color: #333; margin-top: 0;">Message from {$senderName}</h2>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <div style="color: #555; line-height: 1.6;">
            {$htmlContent}
        </div>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px; margin-bottom: 0;">Sent via GoNyva API</p>
    </div>
</body>
</html>
HTML;
    }

    private function validateInput(array $body): array
    {
        $errors = [];

        if (empty($body['name']) || !is_string($body['name']) || strlen(trim($body['name'])) < 2) {
            $errors['name'] = 'Name is required and must be at least 2 characters.';
        } elseif (strlen((string) ($body['name'] ?? '')) > 255) {
            $errors['name'] = 'Name must not exceed 255 characters.';
        }

        if (empty($body['email']) || !is_string($body['email'])) {
            $errors['email'] = 'A valid recipient email address is required.';
        } elseif (strlen($body['email']) > 255) {
            $errors['email'] = 'Email must not exceed 255 characters.';
        } elseif (!filter_var($body['email'], FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'A valid recipient email address is required.';
        }

        if (empty($body['message']) || !is_string($body['message']) || strlen(trim($body['message'])) < 1) {
            $errors['message'] = 'Message content is required.';
        } elseif (strlen((string) ($body['message'] ?? '')) > 50000) {
            $errors['message'] = 'Message must not exceed 50,000 characters.';
        }

        return $errors;
    }

    /**
     * OWASP A03: Sanitize HTML to prevent XSS in emails
     * Allows basic formatting tags, strips dangerous ones
     */
    private function sanitizeHtml(string $html): string
    {
        $allowedTags = '<p><br><strong><b><em><i><u><h1><h2><h3><h4><h5><h6>'
            . '<ul><ol><li><a><img><blockquote><pre><code><hr><span><div><table>'
            . '<thead><tbody><tr><th><td>';

        $html = strip_tags($html, $allowedTags);

        // Remove event handlers (onclick, onerror, etc.)
        $html = preg_replace('/\s*on\w+\s*=\s*["\'][^"\']*["\']/i', '', $html);
        // Remove javascript: URLs
        $html = preg_replace('/href\s*=\s*["\']javascript:[^"\']*["\']/i', 'href="#"', $html);
        $html = preg_replace('/src\s*=\s*["\']javascript:[^"\']*["\']/i', 'src=""', $html);

        return $html;
    }

    private function jsonResponse(Response $response, array $data, int $status = 200): Response
    {
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP));
        return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
    }
}

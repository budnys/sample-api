<?php

declare(strict_types=1);

namespace App\Controllers;

use Monolog\Logger;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * Public contact form endpoint (no JWT required)
 * OWASP A03: Input validation and HTML sanitization
 * OWASP A07: hCaptcha server-side verification instead of JWT
 * OWASP A04: Rate limiting applied via global middleware
 */
class ContactController
{
    private array $smtpSettings;
    private array $captchaSettings;
    private Logger $logger;

    public function __construct(Logger $logger)
    {
        $this->logger = $logger;
        $this->smtpSettings = [
            'host' => $_ENV['SMTP_HOST'] ?? 'mail.nomadtri.com',
            'port' => (int) ($_ENV['SMTP_PORT'] ?? 465),
            'encryption' => $_ENV['SMTP_ENCRYPTION'] ?? 'ssl',
            'user' => $_ENV['SMTP_USER'] ?? '',
            'pass' => $_ENV['SMTP_PASS'] ?? '',
            'from_email' => $_ENV['SMTP_FROM_EMAIL'] ?? 'noreply@nomadtri.com',
            'from_name' => $_ENV['SMTP_FROM_NAME'] ?? 'NomadTri API',
            'to_email' => $_ENV['CONTACT_TO_EMAIL'] ?? $_ENV['SMTP_FROM_EMAIL'] ?? 'noreply@nomadtri.com',
        ];
        $this->captchaSettings = [
            'secret' => $_ENV['HCAPTCHA_SECRET'] ?? '',
            'verify_url' => 'https://api.hcaptcha.com/siteverify',
        ];
    }

    /**
     * POST /api/v1/contact
     *
     * Request body:
     * {
     *   "name": "Sender Name",
     *   "email": "sender@example.com",
     *   "message": "<p>HTML content here</p>",
     *   "captchaToken": "hCaptcha-response-token"
     * }
     *
     * Responses:
     *   200 - Message sent successfully
     *   422 - Validation error
     *   403 - Captcha verification failed
     *   500 - SMTP / server error
     */
    public function submit(Request $request, Response $response): Response
    {
        $body = (array) $request->getParsedBody();

        // OWASP A03: Validate all input
        $errors = $this->validateInput($body);
        if (!empty($errors)) {
            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Validation failed',
                'errors' => $errors,
            ], 422);
        }

        // OWASP A07: Server-side captcha verification (never trust client alone)
        $captchaToken = trim($body['captchaToken'] ?? '');
        if (!$this->verifyCaptcha($captchaToken, $request)) {
            $this->logger->warning('Contact form captcha verification failed', [
                'ip' => $this->getClientIp($request),
            ]);
            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Captcha verification failed. Please try again.',
            ], 403);
        }

        // OWASP A03: Sanitize inputs
        $name = htmlspecialchars(trim($body['name']), ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $senderEmail = strtolower(trim($body['email']));
        $htmlMessage = $this->sanitizeHtml($body['message']);

        try {
            $this->sendEmail($name, $senderEmail, $htmlMessage);

            $this->logger->info('Contact form email sent', [
                'from_name' => $name,
                'from_email' => $senderEmail,
                'ip' => $this->getClientIp($request),
            ]);

            return $this->jsonResponse($response, [
                'success' => true,
                'message' => 'Your message has been sent successfully.',
            ], 200);
        } catch (PHPMailerException $e) {
            $this->logger->error('SMTP error in contact form', [
                'error' => $e->getMessage(),
                'from_email' => $senderEmail,
            ]);

            // OWASP A05: Don't expose internal error details
            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'Failed to send your message. Please try again later.',
            ], 500);
        } catch (\Throwable $e) {
            $this->logger->critical('Unexpected error in contact form', [
                'error' => $e->getMessage(),
            ]);

            return $this->jsonResponse($response, [
                'success' => false,
                'message' => 'An unexpected error occurred. Please try again later.',
            ], 500);
        }
    }

    /**
     * OWASP A07: Verify hCaptcha token server-side
     */
    private function verifyCaptcha(string $token, Request $request): bool
    {
        if (empty($this->captchaSettings['secret'])) {
            $this->logger->warning('HCAPTCHA_SECRET not configured, skipping verification');
            return true; // Allow in dev if not configured
        }

        if (empty($token)) {
            return false;
        }

        $postData = [
            'secret' => $this->captchaSettings['secret'],
            'response' => $token,
            'remoteip' => $this->getClientIp($request),
        ];

        $ch = curl_init($this->captchaSettings['verify_url']);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($postData),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 10,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_HTTPHEADER => ['Content-Type: application/x-www-form-urlencoded'],
        ]);

        $responseBody = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($responseBody === false || $httpCode !== 200) {
            $this->logger->error('hCaptcha verification request failed', [
                'http_code' => $httpCode,
                'curl_error' => $curlError,
            ]);
            return false;
        }

        $result = json_decode($responseBody, true);
        return isset($result['success']) && $result['success'] === true;
    }

    private function sendEmail(string $senderName, string $senderEmail, string $htmlMessage): void
    {
        $mail = new PHPMailer(true);

        // SMTP configuration
        $mail->isSMTP();
        $mail->Host = $this->smtpSettings['host'];
        $mail->Port = $this->smtpSettings['port'];
        $mail->SMTPAuth = true;
        $mail->Username = $this->smtpSettings['user'];
        $mail->Password = $this->smtpSettings['pass'];

        // Encryption
        $encryption = strtolower($this->smtpSettings['encryption']);
        if ($encryption === 'ssl') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS;
        } elseif ($encryption === 'tls') {
            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        }

        // Sender and recipient
        $mail->setFrom($this->smtpSettings['from_email'], $this->smtpSettings['from_name']);
        $mail->addReplyTo($senderEmail, $senderName);
        $mail->addAddress($this->smtpSettings['to_email']);

        // Email content
        $mail->isHTML(true);
        $mail->CharSet = 'UTF-8';
        $mail->Subject = "Contact Form: Message from {$senderName}";
        $mail->Body = $this->wrapHtml($senderName, $senderEmail, $htmlMessage);
        $mail->AltBody = strip_tags(str_replace(['<br>', '<br/>', '<br />'], "\n", $htmlMessage));

        // Timeout
        $mail->Timeout = 30;
        $mail->SMTPKeepAlive = false;

        $mail->send();
    }

    private function wrapHtml(string $senderName, string $senderEmail, string $htmlContent): string
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
        <h2 style="color: #333; margin-top: 0;">New Contact Form Message</h2>
        <div style="background-color: #f8f9fa; border-radius: 6px; padding: 15px; margin-bottom: 20px;">
            <p style="margin: 5px 0; color: #555;"><strong>From:</strong> {$senderName}</p>
            <p style="margin: 5px 0; color: #555;"><strong>Email:</strong> {$senderEmail}</p>
        </div>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <div style="color: #555; line-height: 1.6;">
            {$htmlContent}
        </div>
        <hr style="border: none; border-top: 1px solid #eee; margin: 20px 0;">
        <p style="color: #999; font-size: 12px; margin-bottom: 0;">Sent via NomadTri Contact Form</p>
    </div>
</body>
</html>
HTML;
    }

    /**
     * OWASP A03: Validate all input fields
     */
    private function validateInput(array $body): array
    {
        $errors = [];

        // Name validation
        if (empty($body['name']) || !is_string($body['name']) || strlen(trim($body['name'])) < 2) {
            $errors['name'] = 'Name is required and must be at least 2 characters.';
        } elseif (strlen($body['name']) > 100) {
            $errors['name'] = 'Name must not exceed 100 characters.';
        } elseif (!preg_match('/^[\p{L}\s\'\-\.]+$/u', trim($body['name']))) {
            $errors['name'] = 'Name contains invalid characters.';
        }

        // Email validation (OWASP: use server-side validation, not just regex)
        if (empty($body['email']) || !filter_var($body['email'] ?? '', FILTER_VALIDATE_EMAIL)) {
            $errors['email'] = 'A valid email address is required.';
        } elseif (strlen($body['email']) > 255) {
            $errors['email'] = 'Email must not exceed 255 characters.';
        }

        // Message validation
        if (empty($body['message']) || !is_string($body['message']) || strlen(trim($body['message'])) < 1) {
            $errors['message'] = 'Message content is required.';
        } elseif (strlen($body['message']) > 10000) {
            $errors['message'] = 'Message must not exceed 10,000 characters.';
        }

        // Captcha token
        if (empty($body['captchaToken']) || !is_string($body['captchaToken'])) {
            $errors['captchaToken'] = 'Captcha verification is required.';
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
            . '<ul><ol><li><a><blockquote><pre><code><hr><span><div>';

        $html = strip_tags($html, $allowedTags);

        // Remove event handlers (onclick, onerror, etc.)
        $html = preg_replace('/\s*on\w+\s*=\s*["\'][^"\']*["\']/i', '', $html);
        // Remove javascript: URLs
        $html = preg_replace('/href\s*=\s*["\']javascript:[^"\']*["\']/i', 'href="#"', $html);
        $html = preg_replace('/src\s*=\s*["\']javascript:[^"\']*["\']/i', 'src=""', $html);
        // Remove data: URLs (OWASP: prevent data exfiltration)
        $html = preg_replace('/href\s*=\s*["\']data:[^"\']*["\']/i', 'href="#"', $html);
        // Remove style attributes with expressions/url()
        $html = preg_replace('/style\s*=\s*["\'][^"\']*expression\s*\([^"\']*["\']/i', '', $html);
        $html = preg_replace('/style\s*=\s*["\'][^"\']*url\s*\([^"\']*["\']/i', '', $html);

        return $html;
    }

    /**
     * OWASP: Get client IP safely
     */
    private function getClientIp(Request $request): string
    {
        $headers = ['X-Forwarded-For', 'X-Real-Ip', 'CF-Connecting-IP'];
        foreach ($headers as $header) {
            $value = $request->getHeaderLine($header);
            if (!empty($value)) {
                $ips = array_map('trim', explode(',', $value));
                $ip = $ips[0];
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }

        $serverParams = $request->getServerParams();
        return $serverParams['REMOTE_ADDR'] ?? '0.0.0.0';
    }

    private function jsonResponse(Response $response, array $data, int $status = 200): Response
    {
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP));
        return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
    }
}

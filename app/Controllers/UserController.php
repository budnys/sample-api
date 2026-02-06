<?php

declare(strict_types=1);

namespace App\Controllers;

use Monolog\Logger;
use PDO;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

/**
 * OWASP A01: Broken Access Control - users can only modify their own data (unless admin)
 * OWASP A03: Injection - prepared statements throughout
 */
class UserController
{
    private PDO $db;
    private Logger $logger;

    public function __construct(PDO $db, Logger $logger)
    {
        $this->db = $db;
        $this->logger = $logger;
    }

    /**
     * GET /api/v1/users
     */
    public function list(Request $request, Response $response): Response
    {
        $payload = $request->getAttribute('jwt_payload');

        // OWASP A01: Only admins can list all users
        if (($payload->role ?? '') !== 'admin') {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Forbidden'], 403);
        }

        $page = max(1, (int) ($request->getQueryParams()['page'] ?? 1));
        $limit = min(100, max(1, (int) ($request->getQueryParams()['limit'] ?? 20)));
        $offset = ($page - 1) * $limit;

        $countStmt = $this->db->query('SELECT COUNT(*) FROM users WHERE active = 1');
        $total = (int) $countStmt->fetchColumn();

        $stmt = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at FROM users WHERE active = 1 ORDER BY id DESC LIMIT :limit OFFSET :offset');
        $stmt->bindValue('limit', $limit, PDO::PARAM_INT);
        $stmt->bindValue('offset', $offset, PDO::PARAM_INT);
        $stmt->execute();

        $users = $stmt->fetchAll();
        foreach ($users as &$user) {
            $user['id'] = (int) $user['id'];
        }

        return $this->jsonResponse($response, [
            'success' => true,
            'data' => $users,
            'meta' => [
                'page' => $page,
                'limit' => $limit,
                'total' => $total,
                'total_pages' => (int) ceil($total / $limit),
            ],
        ]);
    }

    /**
     * GET /api/v1/users/{id}
     */
    public function show(Request $request, Response $response, array $args): Response
    {
        $targetId = (int) $args['id'];
        $userId = (int) $request->getAttribute('user_id');
        $payload = $request->getAttribute('jwt_payload');

        // OWASP A01: Users can only view themselves unless admin
        if ($targetId !== $userId && ($payload->role ?? '') !== 'admin') {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Forbidden'], 403);
        }

        $stmt = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = :id AND active = 1 LIMIT 1');
        $stmt->execute(['id' => $targetId]);
        $user = $stmt->fetch();

        if (!$user) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'User not found'], 404);
        }

        $user['id'] = (int) $user['id'];

        return $this->jsonResponse($response, ['success' => true, 'data' => $user]);
    }

    /**
     * PUT /api/v1/users/{id}
     */
    public function update(Request $request, Response $response, array $args): Response
    {
        $targetId = (int) $args['id'];
        $userId = (int) $request->getAttribute('user_id');
        $payload = $request->getAttribute('jwt_payload');

        // OWASP A01: Users can only update themselves unless admin
        if ($targetId !== $userId && ($payload->role ?? '') !== 'admin') {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Forbidden'], 403);
        }

        $body = (array) $request->getParsedBody();
        $updates = [];
        $params = ['id' => $targetId];

        if (isset($body['name']) && is_string($body['name']) && strlen(trim($body['name'])) >= 2) {
            $updates[] = 'name = :name';
            $params['name'] = trim($body['name']);
        }

        if (isset($body['email']) && filter_var($body['email'], FILTER_VALIDATE_EMAIL)) {
            // Check email uniqueness
            $checkStmt = $this->db->prepare('SELECT id FROM users WHERE email = :email AND id != :check_id LIMIT 1');
            $checkStmt->execute(['email' => strtolower(trim($body['email'])), 'check_id' => $targetId]);
            if ($checkStmt->fetch()) {
                return $this->jsonResponse($response, ['success' => false, 'message' => 'Email already in use'], 409);
            }
            $updates[] = 'email = :email';
            $params['email'] = strtolower(trim($body['email']));
        }

        if (isset($body['password']) && strlen($body['password']) >= 8) {
            if (!preg_match('/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/', $body['password'])) {
                return $this->jsonResponse($response, ['success' => false, 'message' => 'Password must contain uppercase, lowercase, and number'], 422);
            }
            $updates[] = 'password = :password';
            $params['password'] = password_hash($body['password'], PASSWORD_BCRYPT, ['cost' => 12]);
        }

        if (empty($updates)) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'No valid fields to update'], 422);
        }

        $updates[] = 'updated_at = NOW()';
        $sql = 'UPDATE users SET ' . implode(', ', $updates) . ' WHERE id = :id AND active = 1';

        $stmt = $this->db->prepare($sql);
        $stmt->execute($params);

        if ($stmt->rowCount() === 0) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'User not found'], 404);
        }

        $this->logger->info('User updated', ['user_id' => $targetId, 'by' => $userId]);

        // Fetch updated user
        $stmt = $this->db->prepare('SELECT id, name, email, role, created_at, updated_at FROM users WHERE id = :id LIMIT 1');
        $stmt->execute(['id' => $targetId]);
        $user = $stmt->fetch();
        $user['id'] = (int) $user['id'];

        return $this->jsonResponse($response, ['success' => true, 'message' => 'User updated', 'data' => $user]);
    }

    /**
     * DELETE /api/v1/users/{id}
     */
    public function delete(Request $request, Response $response, array $args): Response
    {
        $targetId = (int) $args['id'];
        $userId = (int) $request->getAttribute('user_id');
        $payload = $request->getAttribute('jwt_payload');

        // OWASP A01: Only admins can delete users, and no self-delete
        if (($payload->role ?? '') !== 'admin') {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Forbidden'], 403);
        }

        if ($targetId === $userId) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'Cannot delete your own account'], 422);
        }

        // Soft delete
        $stmt = $this->db->prepare('UPDATE users SET active = 0, updated_at = NOW() WHERE id = :id AND active = 1');
        $stmt->execute(['id' => $targetId]);

        if ($stmt->rowCount() === 0) {
            return $this->jsonResponse($response, ['success' => false, 'message' => 'User not found'], 404);
        }

        $this->logger->info('User deleted (soft)', ['target_user_id' => $targetId, 'by' => $userId]);

        return $this->jsonResponse($response, ['success' => true, 'message' => 'User deleted'], 200);
    }

    private function jsonResponse(Response $response, array $data, int $status = 200): Response
    {
        $response->getBody()->write(json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP));
        return $response->withHeader('Content-Type', 'application/json')->withStatus($status);
    }
}

<?php

declare(strict_types=1);

namespace Tests\Controllers;

use App\Controllers\UserController;
use PHPUnit\Framework\TestCase;
use Tests\TestHelper;

class UserControllerTest extends TestCase
{
    use TestHelper;

    private \PDO $pdo;
    private \Monolog\Logger $logger;
    private UserController $controller;

    protected function setUp(): void
    {
        $this->pdo = $this->createMock(\PDO::class);
        $this->logger = $this->createMockLogger();
        $this->controller = new UserController($this->pdo, $this->logger);
    }

    // --- List ---

    public function testListForbiddenForNonAdmin(): void
    {
        $payload = (object) ['role' => 'user'];
        $request = $this->createRequest('GET', '/api/v1/users', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->list($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
        $this->assertEquals('Forbidden', $body['message']);
    }

    public function testListSuccessForAdmin(): void
    {
        $payload = (object) ['role' => 'admin'];

        $countStmt = $this->createMock(\PDOStatement::class);
        $countStmt->method('fetchColumn')->willReturn(2);

        $listStmt = $this->createMock(\PDOStatement::class);
        $listStmt->method('execute')->willReturn(true);
        $listStmt->method('bindValue')->willReturn(true);
        $listStmt->method('fetchAll')->willReturn([
            ['id' => '1', 'name' => 'Admin', 'email' => 'admin@test.com', 'role' => 'admin', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-01'],
            ['id' => '2', 'name' => 'User', 'email' => 'user@test.com', 'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-01'],
        ]);

        $this->pdo->method('query')->willReturn($countStmt);
        $this->pdo->method('prepare')->willReturn($listStmt);

        $request = $this->createRequest('GET', '/api/v1/users?page=1&limit=20', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->list($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertCount(2, $body['data']);
        $this->assertEquals(1, $body['data'][0]['id']);
        $this->assertArrayHasKey('meta', $body);
        $this->assertEquals(2, $body['meta']['total']);
    }

    public function testListPaginationClamps(): void
    {
        $payload = (object) ['role' => 'admin'];

        $countStmt = $this->createMock(\PDOStatement::class);
        $countStmt->method('fetchColumn')->willReturn(0);

        $listStmt = $this->createMock(\PDOStatement::class);
        $listStmt->method('execute')->willReturn(true);
        $listStmt->method('bindValue')->willReturn(true);
        $listStmt->method('fetchAll')->willReturn([]);

        $this->pdo->method('query')->willReturn($countStmt);
        $this->pdo->method('prepare')->willReturn($listStmt);

        // Test with limit > 100 and page < 1
        $request = $this->createRequest('GET', '/api/v1/users?page=-1&limit=999', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->list($request, $response);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals(1, $body['meta']['page']);
        $this->assertEquals(100, $body['meta']['limit']);
    }

    // --- Show ---

    public function testShowForbiddenForNonOwnerNonAdmin(): void
    {
        $payload = (object) ['role' => 'user'];
        $request = $this->createRequest('GET', '/api/v1/users/5', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->show($request, $response, ['id' => '5']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
    }

    public function testShowAllowsOwnerAccess(): void
    {
        $payload = (object) ['role' => 'user'];
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => '2', 'name' => 'User', 'email' => 'user@test.com',
            'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-01',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('GET', '/api/v1/users/2', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->show($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertEquals(2, $body['data']['id']);
    }

    public function testShowAllowsAdminAccessToOtherUsers(): void
    {
        $payload = (object) ['role' => 'admin'];
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn([
            'id' => '5', 'name' => 'Other', 'email' => 'other@test.com',
            'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-01',
        ]);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('GET', '/api/v1/users/5', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->show($request, $response, ['id' => '5']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
    }

    public function testShowReturns404WhenUserNotFound(): void
    {
        $payload = (object) ['role' => 'admin'];
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('fetch')->willReturn(false);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('GET', '/api/v1/users/999', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->show($request, $response, ['id' => '999']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(404, $result->getStatusCode());
    }

    // --- Update ---

    public function testUpdateForbiddenForNonOwnerNonAdmin(): void
    {
        $payload = (object) ['role' => 'user'];
        $request = $this->createRequest('PUT', '/api/v1/users/5', [], ['name' => 'New Name'], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '5']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
    }

    public function testUpdateFailsOnEmptyBody(): void
    {
        $payload = (object) ['role' => 'admin'];
        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [], [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertEquals('No valid fields to update', $body['message']);
    }

    public function testUpdateFailsOnWeakPassword(): void
    {
        $payload = (object) ['role' => 'user'];
        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [
            'password' => 'alllowercase1',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
    }

    public function testUpdateReturns409OnDuplicateEmail(): void
    {
        $payload = (object) ['role' => 'user'];

        $checkStmt = $this->createMock(\PDOStatement::class);
        $checkStmt->method('execute')->willReturn(true);
        $checkStmt->method('fetch')->willReturn(['id' => 5]); // email in use

        $this->pdo->method('prepare')->willReturn($checkStmt);

        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [
            'email' => 'taken@example.com',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(409, $result->getStatusCode());
    }

    public function testUpdateSuccessReturnsUpdatedUser(): void
    {
        $payload = (object) ['role' => 'user'];

        $updateStmt = $this->createMock(\PDOStatement::class);
        $updateStmt->method('execute')->willReturn(true);
        $updateStmt->method('rowCount')->willReturn(1);

        $fetchStmt = $this->createMock(\PDOStatement::class);
        $fetchStmt->method('execute')->willReturn(true);
        $fetchStmt->method('fetch')->willReturn([
            'id' => '2', 'name' => 'Updated Name', 'email' => 'user@test.com',
            'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-02',
        ]);

        $this->pdo->method('prepare')->willReturnOnConsecutiveCalls($updateStmt, $fetchStmt);

        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [
            'name' => 'Updated Name',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('Updated Name', $body['data']['name']);
    }

    public function testUpdateReturns404WhenUserNotFoundAfterUpdate(): void
    {
        $payload = (object) ['role' => 'admin'];

        $updateStmt = $this->createMock(\PDOStatement::class);
        $updateStmt->method('execute')->willReturn(true);
        $updateStmt->method('rowCount')->willReturn(0);

        $this->pdo->method('prepare')->willReturn($updateStmt);

        $request = $this->createRequest('PUT', '/api/v1/users/999', [], [
            'name' => 'New Name',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '999']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(404, $result->getStatusCode());
    }

    public function testUpdateWithEmailSuccess(): void
    {
        $payload = (object) ['role' => 'user'];

        $checkStmt = $this->createMock(\PDOStatement::class);
        $checkStmt->method('execute')->willReturn(true);
        $checkStmt->method('fetch')->willReturn(false); // email not taken

        $updateStmt = $this->createMock(\PDOStatement::class);
        $updateStmt->method('execute')->willReturn(true);
        $updateStmt->method('rowCount')->willReturn(1);

        $fetchStmt = $this->createMock(\PDOStatement::class);
        $fetchStmt->method('execute')->willReturn(true);
        $fetchStmt->method('fetch')->willReturn([
            'id' => '2', 'name' => 'User', 'email' => 'newemail@test.com',
            'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-02',
        ]);

        $this->pdo->method('prepare')->willReturnOnConsecutiveCalls($checkStmt, $updateStmt, $fetchStmt);

        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [
            'email' => 'newemail@test.com',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('newemail@test.com', $body['data']['email']);
    }

    public function testUpdateWithPasswordSuccess(): void
    {
        $payload = (object) ['role' => 'user'];

        $updateStmt = $this->createMock(\PDOStatement::class);
        $updateStmt->method('execute')->willReturn(true);
        $updateStmt->method('rowCount')->willReturn(1);

        $fetchStmt = $this->createMock(\PDOStatement::class);
        $fetchStmt->method('execute')->willReturn(true);
        $fetchStmt->method('fetch')->willReturn([
            'id' => '2', 'name' => 'User', 'email' => 'user@test.com',
            'role' => 'user', 'created_at' => '2026-01-01', 'updated_at' => '2026-01-02',
        ]);

        $this->pdo->method('prepare')->willReturnOnConsecutiveCalls($updateStmt, $fetchStmt);

        $request = $this->createRequest('PUT', '/api/v1/users/2', [], [
            'password' => 'NewSecure1',
        ], [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->update($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
    }

    // --- Delete ---

    public function testDeleteForbiddenForNonAdmin(): void
    {
        $payload = (object) ['role' => 'user'];
        $request = $this->createRequest('DELETE', '/api/v1/users/5', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 2,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->delete($request, $response, ['id' => '5']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(403, $result->getStatusCode());
    }

    public function testDeleteSelfForbidden(): void
    {
        $payload = (object) ['role' => 'admin'];
        $request = $this->createRequest('DELETE', '/api/v1/users/1', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->delete($request, $response, ['id' => '1']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(422, $result->getStatusCode());
        $this->assertEquals('Cannot delete your own account', $body['message']);
    }

    public function testDeleteReturns404WhenNotFound(): void
    {
        $payload = (object) ['role' => 'admin'];
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('rowCount')->willReturn(0);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('DELETE', '/api/v1/users/999', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->delete($request, $response, ['id' => '999']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(404, $result->getStatusCode());
    }

    public function testDeleteSuccessSoftDeletes(): void
    {
        $payload = (object) ['role' => 'admin'];
        $stmt = $this->createMock(\PDOStatement::class);
        $stmt->method('execute')->willReturn(true);
        $stmt->method('rowCount')->willReturn(1);
        $this->pdo->method('prepare')->willReturn($stmt);

        $request = $this->createRequest('DELETE', '/api/v1/users/2', [], null, [], [
            'jwt_payload' => $payload,
            'user_id' => 1,
        ]);
        $response = $this->createResponse();

        $result = $this->controller->delete($request, $response, ['id' => '2']);
        $body = $this->getResponseBody($result);

        $this->assertEquals(200, $result->getStatusCode());
        $this->assertTrue($body['success']);
        $this->assertEquals('User deleted', $body['message']);
    }
}

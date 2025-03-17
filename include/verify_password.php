<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
require_once __DIR__ . '/functions.php';

initCSRFToken();
header('Content-Type: application/json');

// 获取请求头中的CSRF令牌
$headers = getallheaders();
$headerToken = $headers['X-CSRF-Token'] ?? '';

// 解析JSON请求体
$input = json_decode(file_get_contents('php://input'), true) ?? [];
$bodyToken = $input['csrf_token'] ?? '';

// 合并令牌来源
$requestToken = $headerToken ?: $bodyToken;

// 验证CSRF令牌
if (!validateCSRFToken($requestToken)) {
    echo json_encode(['success' => false, 'error' => 'CSRF token验证失败']);
    exit;
}

// 从JSON请求体中获取参数
$messageId = (int)($input['id'] ?? 0);
$password = $input['password'] ?? '';

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        throw new Exception("数据库连接失败: " . $mysqli->connect_error);
    }

    // 查询密码哈希
    $stmt = $mysqli->prepare("SELECT qiaoqiaopass FROM ".DB_PREFIX."book WHERE id = ?");
    if (!$stmt) {
        throw new Exception("预处理语句失败: " . $mysqli->error);
    }
    $stmt->bind_param('i', $messageId);
    $stmt->execute();

    $result = $stmt->get_result();
    if ($result->num_rows === 0) {
        echo json_encode(['success' => false, 'error' => '留言不存在']);
        exit;
    }

    $row = $result->fetch_assoc();
    if (!password_verify($password, $row['qiaoqiaopass'])) {
        echo json_encode(['success' => false, 'error' => '密码错误']);
        exit;
    }

    echo json_encode(['success' => true]);

} catch (Exception $e) {
    error_log("[密码验证错误] " . date('Y-m-d H:i:s') . " - " . $e->getMessage());
    echo json_encode([
        'success' => false,
        'error' => '服务器错误: ' . $e->getMessage()
    ]);
} finally {
    if (isset($stmt)) $stmt->close();
    if (isset($mysqli)) $mysqli->close();
}
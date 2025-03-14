<?php
session_start();
require_once __DIR__.'/include/config.php';

// 统一响应格式
function jsonResponse($success, $message = '', $data = []) {
    header('Content-Type: application/json');
    exit(json_encode(['success' => $success, 'message' => $message, 'data' => $data]));
}

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        throw new Exception("数据库连接失败");
    }
    $mysqli->set_charset('utf8mb4');
} catch (Exception $e) {
    jsonResponse(false, '系统错误，请稍后再试');
}

$input = json_decode(file_get_contents('php://input'), true);

// 验证输入
if (!isset($input['id'], $input['password']) || !is_numeric($input['id']) || empty($input['password'])) {
    jsonResponse(false, '无效请求参数');
}

$stmt = $mysqli->prepare("SELECT qiaoqiaopass FROM ".DB_PREFIX."book WHERE id = ?");
$stmt->bind_param('i', $input['id']);
$stmt->execute();

if ($stmt->error) {
    jsonResponse(false, '系统错误，请稍后再试');
}

$result = $stmt->get_result();

if ($result->num_rows === 0) {
    jsonResponse(false, '留言不存在');
}

$row = $result->fetch_assoc();

if (!password_verify(trim($input['password']), $row['qiaoqiaopass'])) {
    // 记录错误尝试
    $_SESSION['password_attempts'] = ($_SESSION['password_attempts'] ?? 0) + 1;
    
    if ($_SESSION['password_attempts'] >= 3) {
        jsonResponse(false, '错误次数过多，请15分钟后再试');
    }
    
    jsonResponse(false, '密码不正确，剩余尝试次数：'.(3 - $_SESSION['password_attempts']));
}

// 验证成功重置计数器
unset($_SESSION['password_attempts']);
jsonResponse(true, '验证成功', ['content' => $row['content']]);
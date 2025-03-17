<?php
// 在like.php开头添加
session_start();

// 安全头设置
header('Content-Type: application/json');

// CSRF验证
if (!isset($_SERVER['HTTP_X_CSRF_TOKEN']) || 
    !hash_equals($_SESSION['csrf_token'] ?? '', $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '')) {
    http_response_code(403);
    die(json_encode(['error' => 'CSRF token验证失败']));
}

require_once __DIR__.'/functions.php';

try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $mysqli->set_charset('utf8mb4');
    
    // 获取真实IP（支持IPv6）
    $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] 
        ?? $_SERVER['HTTP_X_FORWARDED_FOR']
        ?? $_SERVER['REMOTE_ADDR']
        ?? '::1';
    $ip = inet_pton(explode(',', $ip)[0]);
    
    $messageId = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1]
    ]);
    
    if (!$messageId) {
        throw new InvalidArgumentException('无效的消息ID');
    }
    
    // 获取用户代理和会话ID
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $sessionId = session_id();
    
    // 检查是否已点赞
    $checkStmt = $mysqli->prepare("SELECT id FROM {$_SESSION['db']['prefix']}like 
                                  WHERE message_id = ? AND ip = ? AND user_agent = ? AND session_id = ?");
    $checkStmt->bind_param('isss', $messageId, $ip, $userAgent, $sessionId);
    $checkStmt->execute();
    
    if ($checkStmt->get_result()->num_rows > 0) {
        throw new RuntimeException('您已经点过赞了', 409);
    }
    
    // 使用事务保证数据一致性
    $mysqli->begin_transaction();
    try {
        // 更新点赞数（使用预处理语句）
        $updateStmt = $mysqli->prepare("UPDATE {$_SESSION['db']['prefix']}book 
                                      SET likes = likes + 1 
                                      WHERE id = ?");
        $updateStmt->bind_param('i', $messageId);
        $updateStmt->execute();
        
        // 记录点赞
        $insertStmt = $mysqli->prepare("INSERT INTO {$_SESSION['db']['prefix']}like 
                                       (message_id, ip, user_agent, session_id) 
                                       VALUES (?, ?, ?, ?)");
        $insertStmt->bind_param('isss', $messageId, $ip, $userAgent, $sessionId);
        $insertStmt->execute();
        
        // 获取最新点赞数
        $countStmt = $mysqli->prepare("SELECT likes FROM {$_SESSION['db']['prefix']}book 
                                      WHERE id = ?");
        $countStmt->bind_param('i', $messageId);
        $countStmt->execute();
        $result = $countStmt->get_result();
        $likes = $result->fetch_assoc()['likes'];
        
        $mysqli->commit();
        echo json_encode([
            'success' => true,
            'likes' => $likes
        ]);
    } catch (Exception $e) {
        $mysqli->rollback();
        throw $e;
    }
} catch (InvalidArgumentException $e) {
    http_response_code(400);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
} catch (RuntimeException $e) {
    http_response_code($e->getCode() >= 400 ? $e->getCode() : 400);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
} catch (Exception $e) {
    error_log('[Like Error] '.date('Y-m-d H:i:s').' '
        .$e->getMessage()."\n".$e->getTraceAsString());
    http_response_code(500);
    echo json_encode([
        'success' => false,
        'error' => '服务器内部错误'
    ]);
}
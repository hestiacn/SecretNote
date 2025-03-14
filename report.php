<?php
declare(strict_types=1);
session_start();

// 安全头设置
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'");
header("Access-Control-Allow-Origin: same-origin");

require __DIR__.'/../include/config.php';

try {
    // 仅接受POST请求
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        throw new RuntimeException('Invalid request method', 405);
    }

    // 验证CSRF令牌
    $token = filter_input(INPUT_POST, 'csrf_token', FILTER_SANITIZE_STRING);
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $token)) {
        throw new RuntimeException('CSRF token validation failed', 403);
    }

    // 验证留言ID
    $id = filter_input(INPUT_POST, 'id', FILTER_VALIDATE_INT, [
        'options' => ['min_range' => 1]
    ]);
    if (!$id) {
        throw new InvalidArgumentException('Invalid message ID', 400);
    }

    // 数据库操作
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    $mysqli->begin_transaction();

    try {
        // 更新举报计数
        $stmt = $mysqli->prepare("UPDATE ".DB_PREFIX."book 
            SET report_count = report_count + 1,
                shenhe = IF(report_count >= 2, 0, shenhe)
            WHERE id = ?");
        $stmt->bind_param('i', $id);
        $stmt->execute();

        // 记录日志（需要先创建logs目录）
        $log = [
            'timestamp' => date('c'),
            'id' => $id,
            'ip' => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'],
            'ua' => $_SERVER['HTTP_USER_AGENT'] ?? ''
        ];
        file_put_contents(
            __DIR__.'/../logs/report_'.date('Ym').'.log',
            json_encode($log).PHP_EOL,
            FILE_APPEND | LOCK_EX
        );

        $mysqli->commit();
        echo json_encode(['success' => true]);
    } catch (Exception $e) {
        $mysqli->rollback();
        throw $e;
    } // [!code focus] <-- 内层 try-catch 结束
} catch (Exception $e) { // [!code focus] <-- 外层 catch 开始
    http_response_code($e->getCode() >= 400 ? $e->getCode() : 500);
    echo json_encode([
        'success' => false,
        'error' => $e->getMessage()
    ]);
}
<?php
// 启用严格错误报告
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// 会话管理
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict'
    ]);
}

// 销毁会话
session_unset();
session_destroy();

// 跳转到登录页面
header('Location: adminlogin.php');
exit;
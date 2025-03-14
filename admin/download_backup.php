<?php
declare(strict_types=1);
require_once __DIR__.'/../include/config.php';

session_start([
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'name' => 'ADMIN_SESS'
]);

if (!isset($_SESSION['admin_id']) || $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR'] || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    die("未授权访问");
}

if (!isset($_GET['file'])) {
    die("无效的请求");
}

$filename = basename($_GET['file']);
$backupDir = realpath(__DIR__.'/../backups/');
$filepath = $backupDir . DIRECTORY_SEPARATOR . $filename;

// 验证文件路径
if (!file_exists($filepath) || strpos(realpath($filepath), $backupDir) !== 0) {
    die("无效的备份文件");
}

// 设置下载头
header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="'.basename($filepath).'"');
header('Expires: 0');
header('Cache-Control: must-revalidate');
header('Pragma: public');
header('Content-Length: ' . filesize($filepath));
flush();
readfile($filepath);
exit;
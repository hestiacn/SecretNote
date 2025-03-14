<?php
declare(strict_types=1);
require_once 'include/config.php';
require_once 'include/functions.php';

// 验证会话和权限
if (!isset($_SESSION['admin_id']) || $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR'] || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    die("权限不足");
}

// 构造查询条件
$whereClause = '';
$params = [];

if (!empty($_GET['filter_type'])) {
    $whereClause .= " AND l.action = ?";
    $params[] = $_GET['filter_type'];
}

if (!empty($_GET['filter_start'])) {
    $whereClause .= " AND l.time >= ?";
    $params[] = $_GET['filter_start'];
}

if (!empty($_GET['filter_end'])) {
    $whereClause .= " AND l.time <= ?";
    $params[] = $_GET['filter_end'];
}

// 获取操作日志
$logsQuery = $mysqli->prepare("
    SELECT l.*, a.username 
    FROM ".DB_PREFIX."admin_logs l
    JOIN ".DB_PREFIX."admins a ON l.admin_id = a.id
    WHERE 1=1
    $whereClause
    ORDER BY l.time DESC
");

if ($params) {
    $types = str_repeat('s', count($params));
    $logsQuery->bind_param($types, ...$params);
}

$logsQuery->execute();
$logs = $logsQuery->get_result();

// 设置响应头，告诉浏览器这是一个 CSV 文件
header('Content-Type: text/csv; charset=utf-8');
header('Content-Disposition: attachment; filename=logs_export_'.date('YmdHis').'.csv');

// 创建 CSV 输出
$output = fopen('php://output', 'w');
fputcsv($output, ['时间', '操作类型', '用户ID', '用户名', '详情', 'IP地址']);

while ($log = $logs->fetch_assoc()) {
    fputcsv($output, [
        date('Y-m-d H:i:s', strtotime($log['time'])),
        $log['action'],
        $log['admin_id'],
        $log['username'] ?? '未知用户',
        $log['details'],
        $log['ip_address']
    ]);
}

fclose($output);
exit;
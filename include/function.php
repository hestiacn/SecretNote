<?php
function incrementVisitCount() {
    $logDir = __DIR__ . '/../logs';
    $countFile = $logDir . '/visit_count.log';

    // 自动创建日志目录
    if (!file_exists($logDir)) {
        if (!mkdir($logDir, 0755, true) && !is_dir($logDir)) {
            error_log("无法创建日志目录: $logDir");
            return 0;
        }
    }

    try {
        // 读取当前计数
        $count = file_exists($countFile) ? (int)file_get_contents($countFile) : 0;
        $count++;

        // 写入文件（使用文件锁）
        if (file_put_contents($countFile, $count, LOCK_EX) === false) {
            error_log("无法写入计数文件: $countFile");
            return 0;
        }

        return $count;
    } catch (Exception $e) {
        error_log("访问计数错误: " . $e->getMessage());
        return 0;
    }
}

function getTotalVisitors(): string {
    global $mysqli;
    
    if (!isset($mysqli) || !($mysqli instanceof mysqli)) {
        return '0';
    }

    $result = $mysqli->query("SELECT COUNT(*) AS total FROM gb_page_views");
    if (!$result) {
        error_log("数据库查询失败: " . $mysqli->error);
        return '0';
    }
    
    $row = $result->fetch_assoc();
    return number_format($row['total'] ?? 0);
}
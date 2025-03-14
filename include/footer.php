<?php
// 系统信息获取函数
function getSystemInfo($mysqli) {
    return [
        'php_version' => phpversion(),
        'db_version'  => $mysqli->query("SELECT VERSION()")->fetch_row()[0] ?? '未知',
        'server_soft' => $_SERVER['SERVER_SOFTWARE'] ?? 'N/A',
        'server_time' => date('Y-m-d H:i:s'),
        'client_ip'   => $_SERVER['REMOTE_ADDR'],
        'db_size'     => getDatabaseSize($mysqli), // 自定义函数获取数据库大小
        'memory_usage' => formatBytes(memory_get_usage(true)), // 内存使用格式化
        'load_time'   => round(microtime(true) - $_SERVER["REQUEST_TIME_FLOAT"], 3).'s'
    ];
}

// 示例数据库大小计算函数
function getDatabaseSize($mysqli) {
    $result = $mysqli->query("
        SELECT SUM(data_length + index_length) AS size 
        FROM information_schema.TABLES 
        WHERE table_schema = DATABASE()
    ");
    return $result ? formatBytes($result->fetch_object()->size) : '未知';
}

// 字节格式化函数
function formatBytes($bytes) {
    $units = ['B', 'KB', 'MB', 'GB'];
    $bytes = max($bytes, 0);
    $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
    return round($bytes / pow(1024, $pow), 2).' '.$units[$pow];
}

$sysInfo = getSystemInfo($mysqli);
date_default_timezone_set('Asia/Shanghai');
?>

<footer class="system-footer bg-light mt-5">
    <div class="container-fluid px-4 py-5">
        <div class="row g-5">
            <!-- 系统信息列 -->
            <div class="col-12 col-lg-4">
                <div class="system-metadata card border-0 shadow-sm">
                    <div class="card-body">
                        <h5 class="card-title fw-semibold mb-4">
                            <i class="bi bi-server me-2"></i>系统监控
                        </h5>
                        <dl class="row system-stats">
                            <?php foreach([
                                ['PHP 版本', $sysInfo['php_version'], 'bi-code-square', 'info'],
                                ['MySQL 版本', $sysInfo['db_version'], 'bi-database', 'success'],
                                ['服务器', $sysInfo['server_soft'], 'bi-hdd-stack', 'warning'],
                                ['内存用量', $sysInfo['memory_usage'], 'bi-memory', 'primary'],
                                ['数据库大小', $sysInfo['db_size'], 'bi-file-earmark-binary', 'secondary'],
                                ['响应时间', $sysInfo['load_time'], 'bi-speedometer2', 'dark']
                            ] as $item): ?>
                            <div class="col-6 mb-3">
                                <div class="d-flex align-items-center">
                                    <i class="bi <?= $item[2] ?> fs-5 text-<?= $item[3] ?> me-2"></i>
                                    <div>
                                        <dt class="mb-0 text-muted fs-7"><?= $item[0] ?></dt>
                                        <dd class="mb-0 fw-medium"><?= $item[1] ?></dd>
                                    </div>
                                </div>
                            </div>
                            <?php endforeach ?>
                        </dl>
                    </div>
                </div>
            </div>

            <!-- 导航链接列 -->
            <div class="col-12 col-lg-8">
                <div class="row g-4">
                    <div class="col-6 col-md-4">
                        <h5 class="fw-semibold mb-3"><i class="bi bi-info-circle me-2"></i>关于系统</h5>
                        <ul class="nav flex-column">
                            <li class="nav-item mb-2">
                                <a href="/../README.md" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-git me-1"></i>版本日志
                                </a>
                            </li>
                            <li class="nav-item mb-2">
                                <a href="?action=config" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-gear me-1"></i>系统设置
                                </a>
                            </li>
                            <li class="nav-item mb-2">
                                <a href="?action=logs" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-clipboard-data me-1"></i>操作审计
                                </a>
                            </li>
                        </ul>
                    </div>

                    <div class="col-6 col-md-4">
                        <h5 class="fw-semibold mb-3"><i class="bi bi-shield-check me-2"></i>安全支持</h5>
                        <ul class="nav flex-column">
                            <li class="nav-item mb-2">
                                <a href="#" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-patch-check me-1"></i>系统状态
                                </a>
                            </li>
                            <li class="nav-item mb-2">
                                <a href="?action=config&sub=tutorial" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-journal-text me-1"></i>技术文档
                                </a>
                            </li>
                            <li class="nav-item mb-2">
                                <a href="#" class="nav-link p-0 text-dark hover-primary">
                                    <i class="bi bi-lock me-1"></i>隐私政策
                                </a>
                            </li>
                        </ul>
                    </div>

                    <div class="col-12 col-md-4">
                        <h5 class="fw-semibold mb-3"><i class="bi bi-link-45deg me-2"></i>快速访问</h5>
                        <div class="d-grid gap-2">
                            <a href="?action=messages" class="btn btn-outline-primary btn-sm text-start">
                                <i class="bi bi-chat-dots me-1"></i>留言管理
                            </a>
                            <a href="?action=categories" class="btn btn-outline-success btn-sm text-start">
                                <i class="bi bi-tags me-1"></i>分类管理
                            </a>
                            <a href="?action=config" class="btn btn-outline-info btn-sm text-start">
                                <i class="bi bi-tools me-1"></i>参数配置
                            </a>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- 状态栏 -->
<div class="system-statusbar border-top bg-light py-4">  <!-- 修改背景和边框 -->
    <div class="container-fluid px-4">
        <div class="d-flex flex-wrap justify-content-between align-items-center">
            <div class="d-flex align-items-center">
                <span class="badge bg-white text-dark me-3 fs-6 shadow-sm">  <!-- 移除透明背景 -->
                    <i class="bi bi-clock-history me-1"></i>
                    <span id="realtime-clock"><?= $sysInfo['server_time'] ?></span>
                </span>
                <span class="badge bg-success-subtle text-success me-3 fs-6">  <!-- 使用浅色背景 -->
                    <i class="bi bi-person-check me-1"></i>
                    <?= htmlspecialchars($_SESSION['username'] ?? '管理员') ?>
                </span>
                <span class="badge bg-info-subtle text-info fs-6">  <!-- 使用浅色背景 -->
                    <i class="bi bi-pc-display-horizontal me-1"></i>
                    <?= $sysInfo['client_ip'] ?>
                </span>
            </div>
            <div class="mt-2 mt-sm-0">
                <span class="text-muted fs-6">
                    ©2000 - <?= date('Y') ?> 蓝宝石留言系统 
                    <span class="mx-2">|</span>
                    <a href="#" class="text-body hover-primary">用户协议</a>  <!-- 修改链接颜色 -->
                    <span class="mx-2">|</span>
                    <a href="#" class="text-body hover-primary">隐私政策</a>
                </span>
            </div>
        </div>
    </div>
</div>
</div>
</footer>

<style>
.system-statusbar {
    background: rgba(255,255,255,0.95) !important;  /* 白色半透明背景 */
    border-color: rgba(0,0,0,0.08) !important;      /* 深色边框 */
    backdrop-filter: blur(8px);                     /* 毛玻璃效果 */
}

.system-statusbar .badge {
    border: 1px solid rgba(0,0,0,0.1);             /* 调整边框颜色 */
    backdrop-filter: none;                         /* 移除模糊效果 */
    padding: 0.4em 0.8em;
}

/* 调整移动端显示 */
@media (max-width: 768px) {
    .system-statusbar {
        text-align: center;
    }
    
    .system-statusbar .d-flex {
        flex-direction: column;
        gap: 0.8rem;
    }
    
    .system-statusbar .badge {
        width: 100%;
        justify-content: center;
    }
}

.hover-primary:hover {
    color: var(--bs-primary) !important;
}
</style>

<script>
// 实时时钟更新
function updateRealtimeClock() {
    const options = {
        timeZone: 'Asia/Shanghai',
        hour12: false,
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    };
    document.getElementById('realtime-clock').textContent = 
        new Date().toLocaleString('zh-CN', options);
}
setInterval(updateRealtimeClock, 1000);
</script>
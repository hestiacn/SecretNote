<?php
// 启用严格错误报告
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// 安全头设置
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; 'self'");
header("Referrer-Policy: strict-origin-when-cross-origin");
// 增强会话管理
session_start([
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'name' => 'ADMIN_SESS',
    'use_strict_mode' => true,
    'cookie_lifetime' => 3600 
]);

// 加载配置（使用绝对路径）
define('CONFIG_FILE', __DIR__.'/../include/config.php');
require_once __DIR__ . '/../include/i18n.php';

require_once(CONFIG_FILE);

// 安全函数
function sanitizeInput(string $input): string {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function generateCSRFToken(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken(string $token): bool {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}

// 定义表前缀
$tablePrefix = defined('DB_PREFIX') ? DB_PREFIX : 'gb_';

// 数据库连接
try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        throw new RuntimeException("数据库连接失败: " . $mysqli->connect_error);
    }
} catch (Exception $e) {
    die("数据库错误: " . $e->getMessage());
}

$error = null;
$csrfToken = generateCSRFToken();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        // CSRF验证
        if (!isset($_POST['csrf_token']) || !validateCSRFToken($_POST['csrf_token'])) {
            throw new RuntimeException(__('login_page.error_messages.csrf_token_invalid'));
        }

        // 输入验证
        $user = trim($_POST['user'] ?? '');
        $pass = $_POST['pass'] ?? '';
        if (empty($user) || empty($pass)) {
            throw new InvalidArgumentException(__('login_page.error_messages.empty_credentials'));
        }

        // 数据库查询
        $stmt = $mysqli->prepare("SELECT id, username, password FROM {$tablePrefix}admins WHERE username = ?");
        if (!$stmt) {
            throw new RuntimeException("查询准备失败: " . $mysqli->error);
        }
        $stmt->bind_param('s', $user);
        if (!$stmt->execute()) {
            throw new RuntimeException("查询执行失败: " . $stmt->error);
        }

        $result = $stmt->get_result();
        if ($result->num_rows !== 1) {
            throw new RuntimeException(__('login_page.error_messages.user_not_found'));
        }

        $admin = $result->fetch_assoc();

        // 密码验证
        if (!password_verify($pass, $admin['password'])) {
            error_log(sprintf(__('login_page.logging.login_failed_attempt'), sanitizeInput($user), $_SERVER['REMOTE_ADDR']));
            throw new RuntimeException(__('login_page.error_messages.password_incorrect'));
        }

        // 更新会话
        session_regenerate_id(true);
        $_SESSION['admin_id'] = $admin['id'];
        $_SESSION['admin_user'] = $admin['username'];
        $_SESSION['ip'] = $_SERVER['REMOTE_ADDR'];
        $_SESSION['user_agent'] = $_SERVER['HTTP_USER_AGENT'];

        // 更新最后登录时间
        $updateStmt = $mysqli->prepare("UPDATE {$tablePrefix}admins SET last_login = NOW() WHERE id = ?");
        $updateStmt->bind_param('i', $admin['id']);
        $updateStmt->execute();

        // 跳转到管理后台
        header('Location: dashboard.php');
        exit;

    } catch (Exception $e) {
        $error = $e->getMessage();
        error_log("登录错误: " . $e->getMessage() . " IP: " . ($_SERVER['REMOTE_ADDR'] ?? ''));
        sleep(2);
    }
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= __('login_page.title') ?></title>
    <link rel="icon" href="../assets/image/favicon.ico" type="image/ico">
    <link href="../assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css">
    <link rel="stylesheet" href="../assets/bootstrap-5.3.3/css/logstyles.css">
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="display-5 fw-bold mb-3 text-center"><?= __('login_page.header') ?></h1>
        </div>

        <div class="content">
            <?php if (!empty($error)): ?>
                <div class="alert alert-danger">
                    <i class="bi bi-exclamation-circle"></i>
                    <?= $error ?>
                </div>
            <?php endif; ?>

            <form method="post">
                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                <div class="mb-3">
                    <label class="form-label"><?= __('login_page.form.username_label') ?></label>
                    <input type="text" class="form-control" name="user" required>
                </div>
                <div class="mb-3">
                    <label class="form-label"><?= __('login_page.form.password_label') ?></label>
                    <div class="input-group" id="password-container">
                        <input type="password" class="form-control" name="pass" required id="password-input">
                        <button type="button" class="btn btn-outline-secondary password-toggle" title="显示密码">
                            <i class="bi bi-eye"></i>
                        </button>
                    </div>
                </div>
                <button type="submit" class="btn btn-primary">
                    <i class="bi bi-check2-circle me-2"></i><?= __('login_page.form.submit_button') ?>
                </button>
            </form>
        </div>
    </div>
    <script src="../assets/bootstrap-5.3.3/js/bootstrap.bundle.min.js"></script>
    <script src="../assets/bootstrap-5.3.3/js/script.js"></script>
</body>
</html>
<?php
declare(strict_types=1);
// 基础设置
error_reporting(E_ALL);
ini_set('display_errors', '0');
// 安全头设置（必须最先执行）

header(
    "Content-Security-Policy: " .
    "default-src 'self'; " .
    "script-src 'self' 'nonce-{$cspNonce}' https: 'unsafe-inline'; " .
    "style-src 'self' 'nonce-{$cspNonce}' 'unsafe-inline'; " .
    "img-src 'self' data: https:; " .
    "font-src 'self' data:; " .
    "connect-src 'self'; " .
    "media-src 'self' https:; " .
    "object-src 'none'; " .
    "base-uri 'self'; " .
    "form-action 'self'; " .
    "frame-ancestors 'none'; " .
    "upgrade-insecure-requests;" .
    "report-uri /csp-report;"
);
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Referrer-Policy: strict-origin-when-cross-origin");
// 会话管理（优先处理）

if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_httponly' => true,
        'cookie_samesite' => 'Lax', 
        'read_and_close' => false
    ]);
}

// 加载翻译引擎
require_once __DIR__.'/include/i18n.php';

// 处理语言选择参数
if (isset($_GET['lang'])) {
    $lang = in_array($_GET['lang'], ['zh_CN', 'en_US', 'ja_JP']) ? $_GET['lang'] : 'zh_CN';
    $_SESSION['LANG'] = $lang;
    $LANG = $lang;
}
// 初始化默认语言
$LANG = $_SESSION['LANG'] ?? 'en_US';

define('LOCK_FILE', __DIR__.'/install.lock');
define('CONFIG_FILE', __DIR__.'/include/config.php');

// 安装锁定检测
if (file_exists(LOCK_FILE)) {
    die(sprintf(
        '<div style="text-align: center; color: red;"><h1>%s</h1><p>%s</p></div>',
        htmlspecialchars(__('errors.already_installed'), ENT_QUOTES),
        htmlspecialchars(__('errors.remove_lock_hint'), ENT_QUOTES)
    ));
}
// 安装步骤控制

$step = isset($_GET['step']) ? (int)$_GET['step'] : 1;
$step = max(1, min(5, $step));
// 安全功能定义

function sanitizeInput(string $input): string {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
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

function logInstall(string $message): void {
    $log = sprintf("[%s] %s - %s\n", 
        date('Y-m-d H:i:s'),
        $_SERVER['REMOTE_ADDR'],
        $message
    );
    file_put_contents(__DIR__.'/install.log', $log, FILE_APPEND);
}
// 步骤前置验证

for ($i = 1; $i < $step; $i++) {
    if (!isset($_SESSION["step{$i}"])) {
        header("Location: ?step={$i}");
        exit;
    }
}

// 多语言相关设置
$htmlLang = match ($LANG) {
    'zh_CN' => 'zh-CN',
    'en_US' => 'en',
    'ja_JP' => 'ja',
    default => 'en'
};
// 许可证文件处理
$licenseFile = match ($LANG) {
    'zh_CN' => 'cnlicense.php',
    'en_US' => 'uslicense.php',
    'ja_JP' => 'jplicense.php',
};
define('LICENSE_FILE', __DIR__ . '/' . $licenseFile);

try {
    // 验证许可证文件路径
    $licensePath = realpath(LICENSE_FILE);
    if ($licensePath === false || dirname($licensePath) !== __DIR__) {
        throw new RuntimeException(__('errors.invalid_license_path'));
    }
    
    // 文件可读性检查
    if (!is_readable($licensePath)) {
        throw new RuntimeException(__('errors.license_not_readable'));
    }
    
    // 文件大小限制
    if (filesize($licensePath) > 1024 * 100) {
        throw new RuntimeException(__('errors.license_size_limit'));
    }
    
    $licenseContent = file_get_contents($licensePath);
} catch (Exception $e) {
    $licenseContent = __('errors.license_load_failed') . ': ' . $e->getMessage();
}

// CSRF令牌生成
$error = null;
$csrfToken = generateCSRFToken();

try {
    switch ($step) {
        case 1:
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException(__('errors.csrf_token_invalid'));
                }
                if (!isset($_POST['agree_terms'])) {
                    throw new RuntimeException(__('errors.must_agree_terms'));
                }
                $_SESSION['step1'] = true;
                header('Location: ?step=2');
                exit;
            }
            break;

        case 2:
            $required = [
                __('environment_check.php_version') => version_compare(PHP_VERSION, '8.0.0', '>='),
                __('environment_check.mysqli_extension') => extension_loaded('mysqli'),
                __('environment_check.config_file_writable') => is_writable(dirname(CONFIG_FILE)),
                __('environment_check.gd_library') => extension_loaded('gd'),
                __('environment_check.mbstring_extension') => extension_loaded('mbstring')
            ];

            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException(__('errors.csrf_token_invalid'));
                }
                if (in_array(false, $required, true)) {
                    throw new RuntimeException(__('errors.environment_check_failed'));
                }
                if (!file_exists(CONFIG_FILE) && !touch(CONFIG_FILE)) {
                    throw new RuntimeException(__('errors.unable_to_create_config'));
                }
                chmod(CONFIG_FILE, 0600);
                $_SESSION['step2'] = true;
                header('Location: ?step=3');
                exit;
            }
            break;

        case 3:
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException(__('errors.csrf_token_invalid'));
                }

                $dbConfig = [
                    'host' => sanitizeInput($_POST['host']),
                    'user' => sanitizeInput($_POST['user']),
                    'pass' => $_POST['pass'],
                    'name' => sanitizeInput($_POST['name']),
                    'prefix' => preg_replace('/[^a-z0-9_]/', '', sanitizeInput($_POST['prefix']))
                ];

                // 验证数据库信息
                if (empty($dbConfig['host']) || empty($dbConfig['user']) || empty($dbConfig['name'])) {
                    throw new InvalidArgumentException(__('errors.database_info_required'));
                }

                // 测试数据库连接
                $mysqli = new mysqli(
                    $dbConfig['host'],
                    $dbConfig['user'],
                    $dbConfig['pass'],
                    $dbConfig['name']
                );

                if ($mysqli->connect_errno) {
                    throw new RuntimeException(__('errors.database_connection_failed') . ": {$mysqli->connect_error}");
                }
                // 步骤3连接数据库后增加
                $mysqli->query("DROP TABLE IF EXISTS {$_SESSION['db']['prefix']}book");
                $mysqli->query("DROP TABLE IF EXISTS {$_SESSION['db']['prefix']}typeid");
                $mysqli->query("DROP TABLE IF EXISTS {$_SESSION['db']['prefix']}admins");
                // 检查表前缀冲突
                $result = $mysqli->query("SHOW TABLES LIKE '{$dbConfig['prefix']}%'");
                if ($result->num_rows > 0) {
                    throw new RuntimeException(__('errors.existing_tables_found'));
                }

                $_SESSION['db'] = $dbConfig;
                $_SESSION['step3'] = true;
                header('Location: ?step=4');
                exit;
            }
            break;

        case 4:
            if ($_SERVER['REQUEST_METHOD'] === 'POST') {
                if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException(__('errors.csrf_token_invalid'));
                }

                $admin = [
                    'user' => sanitizeInput($_POST['user']),
                    'pass' => $_POST['pass'],
                    'confirm' => $_POST['confirm']
                ];

                // 验证管理员信息
                if (empty($admin['user']) || empty($admin['pass'])) {
                    throw new InvalidArgumentException(__('errors.admin_info_required'));
                }
                if ($admin['pass'] !== $admin['confirm']) {
                    throw new RuntimeException(__('errors.passwords_do_not_match'));
                }
                if (strlen($admin['pass']) < 8 || !preg_match('/[A-Z]/', $admin['pass']) || !preg_match('/\d/', $admin['pass'])) {
                    throw new RuntimeException(__('errors.password_requirements_not_met'));
                }

                $_SESSION['admin'] = [
                    'user' => $admin['user'],
                    'pass' => password_hash($admin['pass'], PASSWORD_BCRYPT)
                ];
                $_SESSION['step4'] = true;
                header('Location: ?step=5');
                exit;
            }
            break;
case 5:
    // 确保配置目录存在
    $configDir = dirname(CONFIG_FILE);
    if (!is_dir($configDir) && !mkdir($configDir, 0755, true)) {
        throw new RuntimeException("无法创建配置目录: {$configDir}");
    }

    // 获取当前语言的数据
    $LANG = $_SESSION['LANG'] ?? 'zh_CN'; // 从会话中获取语言设置，如果没有则默认为中文
    $currentLangData = $translations[$LANG];

    // 生成配置文件内容
    $configContent = <<<PHP
<?php
// 数据库配置
define('DB_HOST', '{$_SESSION['db']['host']}');
define('DB_USER', '{$_SESSION['db']['user']}');
define('DB_PASS', '{$_SESSION['db']['pass']}');
define('DB_NAME', '{$_SESSION['db']['name']}');
define('DB_PREFIX', '{$_SESSION['db']['prefix']}');
define('DB_CHARSET', 'utf8mb4');

// 对话树配置
define('COMMENT_TREE', true);
define('MAX_DEPTH', 3);
define('REPLY_PER_PAGE', 5);
define('TREE_ORDER', 'DESC');

// 管理员配置
define('ADMIN_USER', '{$_SESSION['admin']['user']}');
define('ADMIN_HASH', '{$_SESSION['admin']['pass']}');

// 安全密钥
define('SITE_KEY', '".bin2hex(random_bytes(32))."');

// 调试模式
define('DEBUG_MODE', false);
PHP;

    // 写入配置文件
    if (file_put_contents(CONFIG_FILE, $configContent) === false) {
        throw new RuntimeException(__('errors.config_write_failed'));
    }
    chmod(CONFIG_FILE, 0644);

    // 数据库连接
    $mysqli = new mysqli(
        $_SESSION['db']['host'],
        $_SESSION['db']['user'],
        $_SESSION['db']['pass'],
        $_SESSION['db']['name']
    );

    // 设置字符集
    if (!$mysqli->set_charset('utf8mb4')) {
        throw new RuntimeException(__('errors.charset_setting_failed'));
    }

    // 开始事务
    $mysqli->begin_transaction();
    try {
        // 禁用外键约束检查
        $mysqli->query("SET FOREIGN_KEY_CHECKS = 0");

        // 按依赖顺序删除表（先子后父）
        $dropTables = [
            'admin_logs',
            'verified_access',
            'like',
            'book',
            'typeid',
            'admins',
            'message_views',
            'users'
        ];

        foreach ($dropTables as $table) {
            $mysqli->query("DROP TABLE IF EXISTS `{$_SESSION['db']['prefix']}{$table}`");
        }

        // 启用外键约束检查
        $mysqli->query("SET FOREIGN_KEY_CHECKS = 1");

        // 创建留言表（修正字段）
	$mysqli->query("CREATE TABLE `{$_SESSION['db']['prefix']}book` (
	    `typeid` INT UNSIGNED DEFAULT 0 COMMENT '".__('database.category_id')."',
	    `id` INT AUTO_INCREMENT PRIMARY KEY COMMENT '".__('database.unique_id')."',
	    `parentid` INT NOT NULL DEFAULT 0 COMMENT '".__('database.parent_id')."',
	    `depth` TINYINT UNSIGNED DEFAULT 0 COMMENT '".__('database.nesting_depth')."',
	    `thetitle` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '".__('database.comment_title')."',
	    `nicheng` VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '".__('database.nickname')."',
	    `homepage` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.homepage')."',
	    `content` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL COMMENT '".__('database.content')."',
	    `allow_html` TINYINT(1) DEFAULT 0 COMMENT '".__('database.allow_html')."',
	    `editor_type` ENUM('markdown','rich-text') DEFAULT 'markdown' COMMENT '".__('database.editor_type')."',
	    `version` INT UNSIGNED DEFAULT 1 COMMENT '".__('database.version')."',
	    `reply` TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.reply')."',
	    `iszhiding` TINYINT(1) UNSIGNED DEFAULT 0 COMMENT '".__('database.is_top')."',
	    `shenhe` TINYINT(1) UNSIGNED DEFAULT 1 COMMENT '".__('database.review_status')."',
	    `is_comment` TINYINT(1) UNSIGNED DEFAULT 1 COMMENT '".__('database.comment_type')."',
	    `qiaoqiao` TINYINT(1) UNSIGNED DEFAULT 0 COMMENT '".__('database.encryption_mode')."',
	    `qiaoqiaopass` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.access_password')."',
	    `ip` VARBINARY(16) NOT NULL COMMENT '".__('database.ip_address')."',
	    `ipshiji` VARCHAR(100) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.ip_location')."',
	    `user_agent` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.browser_fingerprint')."',
	    `time` DATETIME DEFAULT CURRENT_TIMESTAMP COMMENT '".__('database.creation_time')."',
	    `replytime` DATETIME COMMENT '".__('database.reply_time')."',
	    `browsetime` DATETIME COMMENT '".__('database.view_time')."',
	    `media_type` ENUM('image','video','none') DEFAULT 'none' COMMENT '".__('database.media_type')."',
	    `local_image` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.local_image')."',
	    `external_video` VARCHAR(511) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.external_video')."',
	    `video_thumbnail` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci COMMENT '".__('database.video_thumbnail')."',
	    `file_size` INT UNSIGNED COMMENT '".__('database.file_size')."',
	    INDEX `idx_media` (`media_type`),
	    INDEX `idx_thread` (`parentid`,`depth`),
	    FULLTEXT INDEX `idx_search` (`content`,`reply`)
	) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建分类表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}typeid (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            typename VARCHAR(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            addtime DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX uniq_typename (typename(100))
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建管理员表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}admins (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
            password CHAR(60) NOT NULL,
            last_login DATETIME DEFAULT NULL,
            login_attempts TINYINT UNSIGNED DEFAULT 0,
            locked_until DATETIME DEFAULT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX uniq_username (username),
            INDEX idx_login_status (login_attempts, locked_until)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建管理员日志表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}admin_logs (
            id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            admin_id INT UNSIGNED NOT NULL,
            action VARCHAR(50) NOT NULL,
            target_table VARCHAR(30),
            target_id INT UNSIGNED,
            details TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            ip_address VARBINARY(16) NOT NULL,
            user_agent VARCHAR(500) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            INDEX idx_admin_action (admin_id, action),
            FOREIGN KEY (admin_id) REFERENCES {$_SESSION['db']['prefix']}admins(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建验证访问表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}verified_access (
            id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
            message_id INT NOT NULL,
            session_id CHAR(40) NOT NULL,
            access_token CHAR(64) NOT NULL,
            expires_at DATETIME NOT NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX uniq_token (access_token),
            FOREIGN KEY (message_id) REFERENCES {$_SESSION['db']['prefix']}book(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建举报数据表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}reports (
            id INT AUTO_INCREMENT PRIMARY KEY,
            report_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            reporter_id INT DEFAULT NULL,
            reported_id INT NOT NULL,
            reason TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            status ENUM('pending', 'processed', 'ignored') DEFAULT 'pending',
            admin_id INT DEFAULT NULL,
            action_taken TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            FOREIGN KEY (reported_id) REFERENCES {$_SESSION['db']['prefix']}book(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建访问数据表
        $mysqli->query("CREATE TABLE {$_SESSION['db']['prefix']}message_views (
            id INT AUTO_INCREMENT PRIMARY KEY,
            message_id INT NOT NULL,
            user_id INT DEFAULT NULL,
            ip_address VARBINARY(16) NOT NULL,
            view_time DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (message_id) REFERENCES {$_SESSION['db']['prefix']}book(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建点赞表
        $mysqli->query("CREATE TABLE `{$_SESSION['db']['prefix']}like` (
            id INT AUTO_INCREMENT PRIMARY KEY,
            message_id INT NOT NULL,
            ip VARCHAR(45) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            user_agent VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            session_id VARCHAR(128) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE INDEX idx_unique_vote (message_id, ip),
            FOREIGN KEY (message_id) REFERENCES `{$_SESSION['db']['prefix']}book`(id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 创建用户表
        $mysqli->query("CREATE TABLE `{$_SESSION['db']['prefix']}users` (
            `id` INT AUTO_INCREMENT PRIMARY KEY,
            `username` VARCHAR(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL UNIQUE,
            `password` VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
            `created_at` DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // 插入示例留言（修正字段匹配）
        $mysqli->query("INSERT INTO `{$_SESSION['db']['prefix']}book` (
            `id`, `thetitle`, `nicheng`, `content`, `shenhe`,
            `ip`, `ipshiji`, `typeid`, `local_image`, `time`
        ) VALUES (
            1,
            '".__('demo.title')."',
            '".__('demo.default_nickname')."',
            '".$mysqli->real_escape_string(__('demo.content'))."',
            1,
            INET6_ATON('127.0.0.1'),
            '".__('demo.default_location')."',
            0,
            'touxiang/default3/1.gif',
            NOW()
        )");

        // 插入分类数据
        $mysqli->query("INSERT INTO {$_SESSION['db']['prefix']}typeid
            (typename) VALUES
            ('".__('categories.whisper_zone')."'),
            ('".__('categories.user_feedback')."'),
            ('".__('categories.technical_discussion')."'),
            ('".__('categories.product_suggestions')."')");

        // 插入管理员账户
        $stmt = $mysqli->prepare("INSERT INTO {$_SESSION['db']['prefix']}admins
            (username, password) VALUES (?, ?)");
        $stmt->bind_param('ss', $_SESSION['admin']['user'], $_SESSION['admin']['pass']);
        $stmt->execute();

        // 验证表结构
        $requiredTables = ['book', 'typeid', 'admins', 'verified_access', 'admin_logs', 'like', 'message_views', 'users'];
        foreach ($requiredTables as $table) {
            $result = $mysqli->query("SHOW TABLES LIKE '{$_SESSION['db']['prefix']}{$table}'");
            if ($result->num_rows === 0) {
                throw new RuntimeException("关键表 {$table} 创建失败");
            }
        }

        $mysqli->commit();
    } catch (mysqli_sql_exception $e) {
        $mysqli->rollback();
        throw new RuntimeException(__('errors.database_initialization_failed') . ": {$e->getMessage()}");
    }

    // 创建安装锁文件
    $installInfo = [
        'install_time' => date('Y-m-d H:i:s'),
        'db_version' => '2.1.1'
    ];

    if (file_put_contents(
        LOCK_FILE, 
        json_encode($installInfo, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)
    ) === false) {
        throw new RuntimeException(__('errors.lock_file_write_failed'));
    }

    chmod(LOCK_FILE, 0600);

    session_unset();
    session_destroy();
    break;
        }
    } catch (Exception $e) {
        logInstall("安装失败: {$e->getMessage()}");
        $error = $e->getMessage();
    }

    // 生成CSRF令牌
    $csrfToken = generateCSRFToken();
    
?>

<!DOCTYPE html>
<html lang="<?= $htmlLang ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= __('common.title') ?></title>
    <link rel="icon" href="./assets/image/favicon.ico" type="image/ico">
	<link href="/assets/bootstrap-5.3.3/css/bootstrap.min.css" 
	      rel="stylesheet"
	      nonce="<?= $cspNonce ?>"
	      integrity="sha384-QWTKZyjpPEjISv5WaRU9OFeRpok6YctnYmDr5pNlyT2bRjXh0JMhjY6hW+ALEwIH">
    <link href="/assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css" 
          rel="stylesheet"
          nonce="<?= $cspNonce ?>"
          integrity="sha384-XGjxtQfXaH2tnPFa9x+ruJTuLE3Aa6LhHSWRr1XeTyhezb4abCG4ccI5AkVDxqC+">
<style>
.install-wrapper {
  min-height: 100vh;
  background-color: #f8f9fa;
  padding: 2rem 0;
}

.install-container {
  max-width: 960px;
  margin: 0 auto;
  background: white;
  border-radius: 1rem;
  box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
  overflow: hidden;
}

.install-header {
  background-color: #0d6efd;
  color: white;
  padding: 2rem;
  border-radius: 0 0 1rem 1rem;
}

.progress-container {
  height: 8px;
  background-color: #e9ecef;
}

.progress-bar {
  height: 100%;
  background-color: #0d6efd;
  transition: width 0.3s ease;
}

.terms-card {
  border: 1px solid #dee2e6;
  max-height: 60vh;
}

.license-content {
  white-space: pre-wrap;
  font-family: monospace;
  font-size: 0.9em;
  line-height: 1.6;
  margin: 0;
  padding: 1rem;
  height: 60vh;
  overflow-y: auto;
}

.form-control:focus {
  border-color: #86b7fe;
  box-shadow: 0 0 0 0.25rem rgba(13, 110, 253, 0.25);
}

.btn-primary {
  background-color: #0d6efd;
  border-color: #0d6efd;
}

.btn-primary:hover {
  background-color: #0b5ed7;
  border-color: #0b5ed7;
}

.btn-success {
  background-color: #198754;
  border-color: #198754;
}

.btn-success:hover {
  background-color: #157347;
  border-color: #157347;
}

.btn-danger {
  background-color: #dc3545;
  border-color: #dc3545;
}

.btn-danger:hover {
  background-color: #bb2d3b;
  border-color: #bb2d3b;
}

.btn-outline-secondary {
  color: #6c757d;
  border-color: #6c757d;
}

.btn-outline-secondary:hover {
  color: #fff;
  background-color: #6c757d;
}

.install-footer {
  background-color: #f8f9fa;
  padding: 2rem;
  text-align: center;
}
@media (max-width: 992px) {
  .install-container {
      margin: 1rem;
      width: calc(100% - 2rem);
  }
}

@media (max-width: 768px) {
  .install-container {
      border-radius: 0;
      margin: 0;
      width: 100%;
      box-shadow: none;
  }

  .terms-card {
      max-height: 50vh;
  }
}

.form-floating { height: 85px; }

.form-check-input {
    appearance: none;
    width: 20px;
    height: 20px;
    border: 2px solid #ccc;
    border-radius: 4px;
    cursor: pointer;
    position: relative;
}
.form-check .form-check-input {
  float: left;
  margin-left: 1em;
}
.form-check-input:checked::after {
    content: "☑️";
    position: absolute;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    color: #0d6efd;
}
/* 添加到现有样式中 */
.language-switcher {
    z-index: 1000;
}

.language-switcher select {
    background-color: #0d6efd;
    border-color: rgba(255,255,255,0.3);
    color: white;
}

.language-switcher select option {
    background-color: #0d6efd;
    color: white;
}

/* 移动端适配 */
@media (max-width: 768px) {
    .language-switcher {
        position: static !important;
        text-align: center;
        margin: 1rem;
    }
}
.loading-overlay {
  position: fixed;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
  background: rgba(255,255,255,0.8);
  z-index: 9999;
  display: none;
}
</style>
</head>
<body class="install-wrapper">
<!-- 新增语言切换器 -->
<div class="language-switcher position-absolute top-0 end-0 mt-3 me-3">
    <form method="get">
        <!-- 添加提示文本 -->
        <span class="ms-2"><?= __('language_switcher.select_language') ?></span>
		<select name="lang" class="form-select form-select-sm">
		    <?php foreach (['en_US' => 'English', 'zh_CN' => '中文', 'ja_JP' => '日本語'] as $code => $name): ?>
		        <option value="<?= $code ?>" <?= $code === $LANG ? 'selected' : '' ?>>
		            <?= $name ?>
		        </option>
            <?php endforeach; ?>
        </select>
        <input type="hidden" name="step" value="<?= $step ?>">
    </form>
</div>
    <div class="install-container">
        <div class="install-header">
            <div class="d-flex flex-column align-items-center">
			<div style="width: 500px; margin: 0 auto; text-align: center;">
			    <img src="/assets/image/logo.webp" 
			         alt="Icon" 
			         style="max-width: 50%; height: auto; pointer-events: none;">
			</div>
                <h1 class="display-5 fw-bold mb-3"><?= __('common.title') ?></h1>
            </div>
            <div class="d-flex flex-column align-items-center">
                <span class="fs-5 fw-bold mb-3">
                    <?= __('common.version_info') ?>
            <a href="https://www.lanbaoshi.site       " target="_blank" rel="noopener noreferrer" style="color: white; text-decoration: none;">
                <?= __('common.brand') ?>
            </a>
                    <?= __('common.version_suffix') ?>
                </span>
                <span class="fs-5 fw-bold mb-3"><?= __('common.reconstruction_description') ?></span>
            </div>
        </div>

        <div class="step-title">
            <h2><?= __('step_titles.step', ['current' => $step]) ?></h2>
        </div>

        <div class="progress">
            <div class="progress-bar" role="progressbar" style="width: <?= $step * 20 ?>%;" aria-valuenow="<?= $step * 20 ?>" aria-valuemin="0" aria-valuemax="100"></div>
        </div>

        <?php if (!empty($error)): ?>
            <div class="error-message alert alert-danger mt-4">
                <i class="bi bi-exclamation-circle"></i>
                <?= $error ?>
            </div>
        <?php endif; ?>

        <?php switch ($step):
            case 1: ?>
        <div class="card terms-card mb-4">
            <div class="card-header bg-light">
                <h5 class="mb-0"><?= __('step1.license_content') ?></h5>
            </div>
            <div class="license-content" style="white-space: pre-wrap; font-family: monospace; font-size: 0.9em; line-height: 1.6; margin: 0; padding: 1rem; height: 60vh; overflow-y: auto;">
                <?= $licenseContent ?>
            </div>
        </div>

        <form method="post">
            <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
            <div class="form-check mb-4 d-flex align-items-center">
                <input class="form-check-input me-3" type="checkbox" required id="agree_terms" name="agree_terms">
                <label class="form-check-label" for="agree_terms">
                    <?= __('step1.agree_terms') ?>
                </label>
            </div>
            <button type="submit" class="btn btn-primary btn-lg">
                <i class="bi bi-check2-circle me-2"></i><?= __('step1.start_installation') ?>
            </button>
        </form>
            <?php break; case 2: ?>
                <div class="py-4">
                    <h3 class="mb-4"><i class="bi bi-clipboard-check me-2"></i><?= __('step2.environment_check') ?></h3>
                    <div class="list-group">
                        <?php foreach ($required as $name => $status): ?>
                            <div class="list-group-item d-flex align-items-center">
                                <span class="me-auto"><?= $name ?></span>
                                <span class="badge bg-<?= $status ? 'success' : 'danger' ?>">
                                    <?= $status ? '✓ 通过' : '✗ 失败' ?>
                                </span>
                            </div>
                        <?php endforeach; ?>
                    </div>

                    <div class="d-flex justify-content-between mt-4">
                        <a href="?step=1" class="btn btn-outline-secondary">
                            <i class="bi bi-arrow-left me-2"></i><?= __('common.prev') ?>
                        </a>
                        <?php if (!in_array(false, $required, true)): ?>
                            <form method="post" action="?step=2">
                                <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                                <button type="submit" class="btn btn-primary">
                                    <?= __('common.next') ?> <i class="bi bi-arrow-right ms-2"></i>
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>
                </div>
            <?php break; case 3: ?>
                <div class="py-4">
                    <h3 class="mb-4"><i class="bi bi-database me-2"></i><?= __('step3.database_configuration') ?></h3>
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <div class="row g-3">
                            <div class="col-md-6">
                                <label class="form-label"><?= __('step3.database_host') ?></label>
                                <input type="text" class="form-control" name="host" value="localhost" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label"><?= __('step3.database_user') ?></label>
                                <input type="text" class="form-control" name="user" required>
                            </div>
                            <div class="col-12">
                                <label class="form-label"><?= __('step3.database_password') ?></label>
                                <div class="input-group">
                                    <input type="password" class="form-control" name="pass" required>
                                    <button type="button" class="btn btn-outline-secondary password-toggle">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="col-md-8">
                                <label class="form-label"><?= __('step3.database_name') ?></label>
                                <input type="text" class="form-control" name="name" required>
                            </div>
                            <div class="col-md-4">
                                <label class="form-label"><?= __('step3.table_prefix') ?></label>
                                <input type="text" class="form-control" name="prefix" value="gb_" required>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-plug me-2"></i><?= __('step3.test_connection') ?>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            <?php break; case 4: ?>
                <div class="py-4">
                    <h3 class="mb-4"><i class="bi bi-shield-lock me-2"></i><?= __('step4.admin_settings') ?></h3>
                    <form method="post">
                        <input type="hidden" name="csrf_token" value="<?= $csrfToken ?>">
                        <div class="row g-3">
                            <div class="col-12">
                                <label class="form-label"><?= __('step4.admin_username') ?></label>
                                <input type="text" class="form-control" name="user" required>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label"><?= __('step4.login_password') ?></label>
                                <div class="input-group">
                                    <input type="password" class="form-control" name="pass" required>
                                    <button type="button" class="btn btn-outline-secondary password-toggle">
                                        <i class="bi bi-eye"></i>
                                    </button>
                                </div>
                            </div>
                            <div class="col-md-6">
                                <label class="form-label"><?= __('step4.confirm_password') ?></label>
                                <input type="password" class="form-control" name="confirm" required>
                            </div>
                            <div class="col-12">
                                <div class="alert alert-info">
                                    <i class="bi bi-info-circle me-2"></i>
                                    <?= __('step4.password_requirements') ?>
                                </div>
                            </div>
                            <div class="col-12">
                                <button type="submit" class="btn btn-primary">
                                    <?= __('step4.create_admin_account') ?>
                                </button>
                            </div>
                        </div>
                    </form>
                </div>
            <?php break; case 5: ?>
                <div class="text-center py-5">
                    <div class="mb-4">
                        <i class="bi bi-check-circle-fill text-success" style="font-size: 5rem"></i>
                    </div>
                    <h2 class="mb-3"><?= __('step5.installation_success') ?></h2>
                    <p class="text-muted mb-4"><?= __('step5.guestbook_ready') ?></p>
                    <div class="alert alert-warning text-start">
                        <h5><i class="bi bi-shield-exclamation me-2"></i><?= __('step5.security_recommendations') ?></h5>
                        <ul class="mb-0">
                            <li><?= __('step5.delete_install_file') ?></li>
                            <li><?= __('step5.set_config_readonly') ?></li>
                            <li><?= __('step5.configure_web_server') ?></li>
                        </ul>
                    </div>
                    <div class="d-grid gap-3 col-md-8 mx-auto">
                        <a href="../" class="btn btn-success btn-lg">
                            <i class="bi bi-house-door me-2"></i><?= __('step5.visit_homepage') ?>
                        </a>
                        <a href="../admin/adminlogin.php" class="btn btn-primary btn-lg">
                            <i class="bi bi-gear me-2"></i><?= __('step5.admin_console') ?>
                        </a>
                    </div>
                </div>
            <?php endswitch; ?>
    </div>
   
<script>
document.querySelector('select[name="lang"]').addEventListener('change', function() {
  const form = this.closest('form');
  if (!form) return;
  const overlay = document.createElement('div');
  overlay.className = 'loading-overlay';
  overlay.innerHTML = '<div class="spinner-border text-primary"></div>';
  document.body.appendChild(overlay);
  form.submit();
});

document.body.addEventListener('click', function(event) {
    if (event.target.closest('.password-toggle')) {
        const btn = event.target.closest('.password-toggle');
        const input = btn.previousElementSibling;
        const icon = btn.querySelector('i');
        if (input && input.tagName === 'INPUT') {
            input.type = input.type === 'password' ? 'text' : 'password';
            icon.classList.toggle('bi-eye');
            icon.classList.toggle('bi-eye-slash');
        }
    }
});
</script>
</body>
</html>

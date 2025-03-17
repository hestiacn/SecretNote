<?php
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// 安全头设置
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'");
header("Referrer-Policy: strict-origin-when-cross-origin");

// 加载配置文件
$contentJsonPath = __DIR__ . '/../include/content.json';
$dbConfigPath = __DIR__ . '/../include/config.php';

if (!file_exists($contentJsonPath) || !file_exists($dbConfigPath)) {
    die("<h1 style='color:red'>配置文件缺失，请检查安装！</h1>");
}
require_once $dbConfigPath;  // 先加载数据库配置
require_once __DIR__ . '/../assets/htmlpurifier/library/HTMLPurifier.auto.php';
$contentConfig = json_decode(file_get_contents($contentJsonPath), true);
if (json_last_error() !== JSON_ERROR_NONE) {
    die("<h1>content.json格式错误</h1>");
}

// 数据库连接类
class SafeDB extends mysqli {
    public function __construct($host, $user, $pass, $db) {
        parent::__construct($host, $user, $pass, $db);
        if ($this->connect_errno) {
            throw new RuntimeException("数据库连接失败: ".$this->connect_error);
        }
        $this->set_charset('utf8mb4');
    }
}

try {
    $mysqli = new SafeDB(DB_HOST, DB_USER, DB_PASS, DB_NAME);
} catch (Exception $e) {
    die("<div class='alert alert-danger'>数据库错误：".$e->getMessage()."</div>");
}

// 会话管理
session_start([
    'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict',
    'name' => 'ADMIN_SESS'
]);

// 访问控制
if (!isset($_SESSION['admin_id']) || $_SESSION['ip'] !== $_SERVER['REMOTE_ADDR'] || $_SESSION['user_agent'] !== $_SERVER['HTTP_USER_AGENT']) {
    session_destroy();
    header('Location: adminlogin.php');
    exit;
}

// 功能函数
function sanitizeInput($input) {
    // 确保输入是字符串类型
    if (!is_string($input)) {
        $input = strval($input);
    }
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function validateCSRFToken($token) {
    return hash_equals($_SESSION['csrf_token'] ?? '', $token);
}
// 在 sanitizeInput 函数后添加（约第 68 行后）
function sanitizeHTML($input) {
    static $purifier = null;
    if ($purifier === null) {
        $config = HTMLPurifier_Config::createDefault();
        $config->set('HTML.Allowed', 'p,br,img[src|alt|width|height],iframe[src|width|height|frameborder|allowfullscreen],a[href]');
        $config->set('URI.AllowedSchemes', ['http' => true, 'https' => true, 'data' => true]);
        $config->set('HTML.SafeIframe', true);
        $config->set('URI.SafeIframeRegexp', '%^(https?:)?//(www\.youtube(?:-nocookie)?\.com/embed/|player\.bilibili\.com/)%');
        $purifier = new HTMLPurifier($config);
    }
    return $purifier->purify($input);
}
// 记录操作日志的函数
function logAdminAction($adminId, $action, $targetTable = null, $targetId = null, $details = '', $ipAddress, $userAgent) {
    global $mysqli, $_SESSION;
    
    $stmt = $mysqli->prepare("INSERT INTO ".DB_PREFIX."admin_logs 
        (admin_id, action, target_table, target_id, details, ip_address, user_agent) 
        VALUES (?, ?, ?, ?, ?, INET_ATON(?), ?)");
    
    $stmt->bind_param("isissis", 
        $adminId, 
        $action, 
        $targetTable, 
        $targetId, 
        $details, 
        $ipAddress, 
        $userAgent
    );
    
    $stmt->execute();
    $stmt->close();
}

// 处理表单提交
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
            throw new RuntimeException('CSRF验证失败');
        }
        // 1. 处理数据库备份
        if (isset($_POST['action']) && $_POST['action'] === 'create_backup') {
            $backupDir = __DIR__ . '/../backups/';
            
            // 加强目录创建验证
            if (!file_exists($backupDir) && !mkdir($backupDir, 0755, true)) {
                throw new RuntimeException('无法创建备份目录');
            }

            // 生成带时间戳的文件名
            $backupFileName = 'backup_' . date('Ymd_His') . '.sql';
            $backupPath = $backupDir . $backupFileName;

            // 获取所有表
            $tables = $mysqli->query("SHOW TABLES")->fetch_all(MYSQLI_NUM);
            
            // 构建SQL内容
            $sqlContent = "-- Bluegem Guestbook Backup\n";
            $sqlContent .= "-- Generated: " . date('Y-m-d H:i:s') . "\n\n";
            
            foreach ($tables as $table) {
                $tableName = $table[0];
                
                // 获取表结构
                $createTable = $mysqli->query("SHOW CREATE TABLE `$tableName`")->fetch_row();
                $sqlContent .= "\n-- Table structure for $tableName\n";
                $sqlContent .= "DROP TABLE IF EXISTS `$tableName`;\n";
                $sqlContent .= $createTable[1] . ";\n\n";
                
			// 获取表数据
			$rows = $mysqli->query("SELECT * FROM `$tableName`");
			if ($rows->num_rows > 0) {
			    $sqlContent .= "-- Data for $tableName\n";
			    while ($row = $rows->fetch_assoc()) {
			        $values = [];
			        foreach ($row as $value) {
			            if ($value === null) {
			                $values[] = 'NULL';
			            } else {
			                $values[] = "'" . $mysqli->real_escape_string($value) . "'";
			            }
			        }
			        $sqlContent .= "INSERT INTO `$tableName` VALUES (" . implode(", ", $values) . ");\n";
			    }
			    $sqlContent .= "\n";
			}
             }
            // 写入文件
            if (file_put_contents($backupPath, $sqlContent)) {
                $_SESSION['success'] = '备份创建成功: ' . $backupFileName;
                
                // 记录日志
                logAdminAction(
                    $_SESSION['admin_id'],
                    "backup_create",
                    null,
                    null,
                    "备份文件: " . $backupFileName,
                    $_SERVER['REMOTE_ADDR'],
                    $_SERVER['HTTP_USER_AGENT']
                );

                // 清理旧备份 (保留最近30个)
                $backups = glob($backupDir . 'backup_*.sql');
                if (count($backups) > 30) {
                    usort($backups, function($a, $b) {
                        return filemtime($b) - filemtime($a); // 修正排序顺序
                    });
                    $oldBackups = array_slice($backups, 30);
                    foreach ($oldBackups as $old) {
                        unlink($old);
                    }
                }
            } else {
                throw new RuntimeException('备份文件写入失败');
            }
            
            header("Location: " . $_SERVER['HTTP_REFERER']);
            exit;
        }

        // 2. 处理备份删除
        if (isset($_POST['action']) && $_POST['action'] === 'delete_backup') {
            $filename = basename($_POST['filename']);
            $backupDir = realpath(__DIR__.'/../backups/');
            $filepath = $backupDir . DIRECTORY_SEPARATOR . $filename;

            // 加强路径验证
            $realPath = realpath($filepath);
            if (!$realPath || strpos($realPath, $backupDir) !== 0) {
                throw new RuntimeException('无效的备份文件路径');
            }

            if (!unlink($realPath)) {
                throw new RuntimeException('文件删除失败');
            }

            $_SESSION['success'] = '备份文件已删除';
            logAdminAction(
                $_SESSION['admin_id'],
                "backup_delete",
                null,
                null,
                "备份文件: " . $filename,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT']
            );
            
            header("Location: ".$_SERVER['HTTP_REFERER']);
            exit;
        }
        // 处理分类管理
        if (isset($_POST['category_action'])) {
            $categoryId = intval($_POST['category_id'] ?? 0);
            $categoryName = sanitizeInput($_POST['name'] ?? '');

            switch ($_POST['category_action']) {
                case 'add':
                    if (empty($categoryName)) {
                        throw new RuntimeException('分类名称不能为空');
                    }
                    $result = $mysqli->query("INSERT INTO ".DB_PREFIX."typeid (typename) VALUES ('".$categoryName."')");
                    if (!$result) {
                        throw new RuntimeException('添加分类失败：'.$mysqli->error);
                    }
                    $_SESSION['success'] = '分类添加成功';
                    
                    // 记录日志
                    logAdminAction(
                        $_SESSION['admin_id'],
                        "category_add",
                        "typeid",
                        $mysqli->insert_id,
                        "分类名称: " . $categoryName,
                        $_SERVER['REMOTE_ADDR'],
                        $_SERVER['HTTP_USER_AGENT']
                    );
                    break;

                case 'edit':
                    if (empty($categoryName) || $categoryId <= 0) {
                        throw new RuntimeException('分类名称或ID无效');
                    }
                    $result = $mysqli->query("UPDATE ".DB_PREFIX."typeid SET typename='".$categoryName."' WHERE id=".$categoryId);
                    if (!$result) {
                        throw new RuntimeException('修改分类失败：'.$mysqli->error);
                    }
                    $_SESSION['success'] = '分类修改成功';
                    
                    // 记录日志
                    logAdminAction(
                        $_SESSION['admin_id'],
                        "编辑分类",
                        "typeid",
                        $categoryId,
                        "分类名称: " . $categoryName,
                        $_SERVER['REMOTE_ADDR'],
                        $_SERVER['HTTP_USER_AGENT']
                    );
                    break;

                case 'delete':
                    if ($categoryId <= 0) {
                        throw new RuntimeException('分类ID无效');
                    }
                    $result = $mysqli->query("DELETE FROM ".DB_PREFIX."typeid WHERE id=".$categoryId);
                    if (!$result) {
                        throw new RuntimeException('删除分类失败：'.$mysqli->error);
                    }
                    $_SESSION['success'] = '分类删除成功';
                    
                    // 记录日志
                    logAdminAction(
                        $_SESSION['admin_id'],
                        "category_delete",
                        "typeid",
                        $categoryId,
                        "分类名称: " . $categoryName,
                        $_SERVER['REMOTE_ADDR'],
                        $_SERVER['HTTP_USER_AGENT']
                    );
                    break;

                default:
                    throw new RuntimeException('无效的操作类型');
            }

            header("Location: ".$_SERVER['REQUEST_URI']);
            exit;
        }

        // 处理留言状态更改
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['shenhe'])) {
            try {
                if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
                    throw new RuntimeException('CSRF验证失败');
                }

                $messageId = intval($_POST['message_id'] ?? 0);
                if ($messageId <= 0) {
                    throw new RuntimeException('留言ID无效');
                }

                $shenhe = intval($_POST['shenhe']);
                if (!in_array($shenhe, [0, 1])) {
                    throw new RuntimeException('无效的状态值');
                }

                $result = $mysqli->query("UPDATE ".DB_PREFIX."book SET shenhe=".$shenhe." WHERE id=".$messageId);
                if (!$result) {
                    throw new RuntimeException('状态更新失败：'.$mysqli->error);
                }

                $_SESSION['success'] = '留言审核状态已更新';
                
			// 记录日志
			logAdminAction(
			    $_SESSION['admin_id'],
			    "留言审核操作",
			    "book",
			    $messageId,
			    "状态: " . ($shenhe ? '已审核' : '待审核'),
			    $_SERVER['REMOTE_ADDR'],
			    $_SERVER['HTTP_USER_AGENT']
			);
                
                header("Location: ".$_SERVER['REQUEST_URI']);
                exit;
            } catch (Exception $e) {
                $_SESSION['error'] = $e->getMessage();
                header("Location: ".$_SERVER['REQUEST_URI']);
                exit;
            }
        }
        // 处理留言管理
		// 处理单独删除留言
		if (isset($_POST['action']) && $_POST['action'] === 'delete') {
		    $messageId = intval($_POST['message_id'] ?? 0);
		    if ($messageId <= 0) {
		        throw new RuntimeException('留言ID无效');
		    }
		
		    $result = $mysqli->query("DELETE FROM ".DB_PREFIX."book WHERE id=".$messageId);
		    if (!$result) {
		        throw new RuntimeException('删除留言失败：'.$mysqli->error);
		    }
		    $_SESSION['success'] = '留言删除成功';
		    
		    // 记录日志
		    logAdminAction(
		        $_SESSION['admin_id'],
		        "留言删除",
		        "book",
		        $messageId,
		        "",
		        $_SERVER['REMOTE_ADDR'],
		        $_SERVER['HTTP_USER_AGENT']
		    );
		    
		    header("Location: ".$_SERVER['REQUEST_URI']);
		    exit;
		}
		// 处理单独编辑留言
		if (isset($_POST['action']) && $_POST['action'] === 'edit') {
		    $messageId = intval($_POST['message_id'] ?? 0);
		    if ($messageId <= 0) {
		        throw new RuntimeException('留言ID无效');
		    }
		
		    $thetitle = sanitizeInput($_POST['thetitle'] ?? '');
		    $nicheng = sanitizeInput($_POST['nicheng'] ?? '');
		    $content = sanitizeHTML($_POST['content'] ?? '');
		    $qiaoqiao = isset($_POST['qiaoqiao']) ? 1 : 0;
		    $shenhe = isset($_POST['shenhe']) ? 1 : 0;
		
		    $result = $mysqli->query("UPDATE ".DB_PREFIX."book SET thetitle='".$thetitle."', nicheng='".$nicheng."', content='".$content."', qiaoqiao=".$qiaoqiao.", shenhe=".$shenhe." WHERE id=".$messageId);
		    if (!$result) {
		        throw new RuntimeException('修改留言失败：'.$mysqli->error);
		    }
		    $_SESSION['success'] = '留言修改成功';
		    
		    // 记录日志
		    logAdminAction(
		        $_SESSION['admin_id'],
		        "message_edit",
		        "book",
		        $messageId,
		        "标题: " . $thetitle . ", 内容: " . $content,
		        $_SERVER['REMOTE_ADDR'],
		        $_SERVER['HTTP_USER_AGENT']
		    );
		    
		    header("Location: ".$_SERVER['REQUEST_URI']);
		    exit;
		}
		// 处理单独回复留言
		if (isset($_POST['action']) && $_POST['action'] === 'reply') {
		    $messageId = intval($_POST['message_id'] ?? 0);
		    if ($messageId <= 0) {
		        throw new RuntimeException('留言ID无效');
		    }
		
		    $replyContent = sanitizeInput($_POST['reply_content'] ?? '');
		    $currentTime = date('Y-m-d H:i:s');
		
		    $result = $mysqli->query("UPDATE ".DB_PREFIX."book SET reply='".$replyContent."', replytime='".$currentTime."' WHERE id=".$messageId);
		    if (!$result) {
		        throw new RuntimeException('回复留言失败：'.$mysqli->error);
		    }
		    $_SESSION['success'] = '留言回复成功';
		    
		    // 记录日志
		    logAdminAction(
		        $_SESSION['admin_id'],
		        "留言回复",
		        "book",
		        $messageId,
		        "回复内容: " . $replyContent,
		        $_SERVER['REMOTE_ADDR'],
		        $_SERVER['HTTP_USER_AGENT']
		    );
		    
		    header("Location: ".$_SERVER['REQUEST_URI']);
		    exit;
		}
     // 处理批量操作
	if (isset($_POST['bulk_action'])) {
	    $action = $_POST['action'] ?? '';
	    $messageIds = $_POST['message_ids'] ?? array();
	
	    if (empty($action) || empty($messageIds)) {
	        throw new RuntimeException('请选择操作和留言');
	    }
	
	    $messageIds = array_map('intval', $messageIds);
	    $messageIds = implode(',', $messageIds);
	
	    switch ($action) {
	        case 'delete':
	            $result = $mysqli->query("DELETE FROM ".DB_PREFIX."book WHERE id IN (".$messageIds.")");
	            if (!$result) {
	                throw new RuntimeException('批量删除失败：'.$mysqli->error);
	            }
	            $_SESSION['success'] = '批量删除成功';
	            
	            // 记录日志
	            logAdminAction(
	                $_SESSION['admin_id'],
	                "message_bulk_delete",
	                "book",
	                null,
	                "批量删除留言ID: " . $messageIds,
	                $_SERVER['REMOTE_ADDR'],
	                $_SERVER['HTTP_USER_AGENT']
	            );
	            break;

                case 'approve':
                    $result = $mysqli->query("UPDATE ".DB_PREFIX."book SET shenhe = 1 WHERE id IN (".$messageIds.")");
                    if (!$result) {
                        throw new RuntimeException('批量通过失败：'.$mysqli->error);
                    }
                    $_SESSION['success'] = '批量通过成功';
                    
                    // 记录日志
                    logAdminAction(
                        $_SESSION['admin_id'],
                        "message_bulk_approve",
                        "book",
                        null,
                        "批量审核通过留言ID: " . $messageIds,
                        $_SERVER['REMOTE_ADDR'],
                        $_SERVER['HTTP_USER_AGENT']
                    );
                    break;

                case 'unapprove':
                    $result = $mysqli->query("UPDATE ".DB_PREFIX."book SET shenhe = 0 WHERE id IN (".$messageIds.")");
                    if (!$result) {
                        throw new RuntimeException('设置为未审核失败：'.$mysqli->error);
                    }
                    $_SESSION['success'] = '设置为未审核成功';
                    
                    // 记录日志
                    logAdminAction(
                        $_SESSION['admin_id'],
                        "message_bulk_unapprove",
                        "book",
                        null,
                        "批量设置未审核留言ID: " . $messageIds,
                        $_SERVER['REMOTE_ADDR'],
                        $_SERVER['HTTP_USER_AGENT']
                    );
                    break;

                default:
                    throw new RuntimeException('无效的操作类型');
            }

            header("Location: ".$_SERVER['REQUEST_URI']);
            exit;
        }

        // 保存配置文件
        if (isset($_POST['action']) && $_POST['action'] === 'save_config') {
            $configType = $_POST['config_type'] ?? 'content';
            $targetPath = $configType === 'content' ? $contentJsonPath : $dbConfigPath;

            $content = $_POST['config_content'] ?? '';

            // 仅对content.json进行JSON验证
            if ($configType === 'content') {
                $decoded = json_decode($content);
                if(json_last_error() !== JSON_ERROR_NONE) {
                    throw new RuntimeException('JSON格式错误：'.json_last_error_msg());
                }
            }

            if (!is_writable($targetPath)) {
                throw new RuntimeException('配置文件不可写');
            }

            // 创建备份（区分不同配置类型）
            $backupDir = __DIR__ . '/../backups/'; // 修改备份目录路径
            if (!file_exists($backupDir)) {
                mkdir($backupDir, 0755, true); // 如果目录不存在则创建
            }

            $backupPrefix = $configType === 'content' ? 'content_' : 'db_';
            $backupContent = file_get_contents($targetPath);
            $backupName = $backupPrefix . date('YmdHis') . '.bak';
            file_put_contents($backupDir . $backupName, $backupContent);

            if (file_put_contents($targetPath, $content) === false) {
                throw new RuntimeException('配置保存失败');
            }

            $_SESSION['success'] = '配置已保存并创建备份：' . $backupName . '，备份文件已存储在 backups 目录中';
            
            // 记录日志
            logAdminAction(
                $_SESSION['admin_id'],
                "配置保存",
                null,
                null,
                "配置类型: " . $configType . ", 备份文件: " . $backupName,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT']
            );
            
            header("Location: " . $_SERVER['REQUEST_URI']);
            exit;
        }

        // 删除备份
        if (isset($_POST['action']) && $_POST['action'] === 'delete_backup') {
            $filename = basename($_POST['filename']);
            $filepath = realpath(__DIR__.'/../backups/'.$filename);

            // 验证路径在备份目录内
            if(strpos($filepath, realpath(__DIR__.'/../backups/')) !== 0) {
                throw new RuntimeException('无效的备份文件路径');
            }

            if(unlink($filepath)) {
                $_SESSION['success'] = '备份文件已删除';
            } else {
                throw new RuntimeException('文件删除失败');
            }
            
            // 记录日志
            logAdminAction(
                $_SESSION['admin_id'],
                "backup_delete",
                null,
                null,
                "备份文件: " . $filename,
                $_SERVER['REMOTE_ADDR'],
                $_SERVER['HTTP_USER_AGENT']
            );
            
            header("Location: ".$_SERVER['REQUEST_URI']);
            exit;
        }

    } catch (Exception $e) {
        $_SESSION['error'] = $e->getMessage();
        header("Location: ".$_SERVER['REQUEST_URI']);
        exit;
    }
}

// 页面参数处理
$validActions = ['messages', 'categories', 'logs', 'config'];
$action = in_array($_GET['action'] ?? '', $validActions) ? $_GET['action'] : 'messages';
$currentPage = max(1, $_GET['page'] ?? 1);
$perPage = 20;
$filter = $_GET['filter'] ?? '';

// 获取分类数据
if ($action === 'categories') {
    $categories = $mysqli->query("SELECT * FROM ".DB_PREFIX."typeid ORDER BY id")->fetch_all(MYSQLI_ASSOC);
}

// 获取留言数据
if ($action === 'messages') {
    $offset = ($currentPage - 1) * $perPage;
    
    // 构造查询条件
    $whereClause = '';
    if ($filter === 'secret') {
        $whereClause = 'WHERE qiaoqiao = 1';
    } elseif ($filter === 'pending') {
        $whereClause = 'WHERE shenhe = 0';
    }
    
    $messages = $mysqli->query("
        SELECT SQL_CALC_FOUND_ROWS * 
        FROM ".DB_PREFIX."book 
        $whereClause
        ORDER BY time DESC 
        LIMIT $perPage OFFSET $offset
    ")->fetch_all(MYSQLI_ASSOC);
    
    $total = $mysqli->query("SELECT FOUND_ROWS()")->fetch_row()[0];
    $totalPages = ceil($total / $perPage);
}

// 获取统计信息
$stats = $mysqli->query("
    SELECT 
        COUNT(*) AS total,
        SUM(qiaoqiao) AS secrets,
        SUM(shenhe = 0) AS pending
    FROM ".DB_PREFIX."book
")->fetch_assoc();

// 日志模块
if ($action === 'logs') {
    // 筛选条件
    $filterType = $_GET['filter_type'] ?? '';
    $filterAdmin = $_GET['filter_admin'] ?? '';
    $filterStart = $_GET['filter_start'] ?? '';
    $filterEnd = $_GET['filter_end'] ?? '';
    
    // 构造查询条件
    $whereClause = "1=1";
    
    if (!empty($filterType)) {
        $whereClause .= " AND action = '" . $mysqli->real_escape_string($filterType) . "'";
    }
    
    if (!empty($filterAdmin)) {
        $whereClause .= " AND admin_id = (SELECT id FROM {$_SESSION['db']['prefix']}admins WHERE username = '" . 
            $mysqli->real_escape_string($filterAdmin) . "')";
    }
    
    if (!empty($filterStart)) {
        $whereClause .= " AND created_at >= '" . $mysqli->real_escape_string($filterStart) . "'";
    }
    
    if (!empty($filterEnd)) {
        $whereClause .= " AND created_at <= '" . $mysqli->real_escape_string($filterEnd) . "'";
    }
    
    // 分页
    $perPage = 20;
    $currentPage = max(1, $_GET['page'] ?? 1);
    $offset = ($currentPage - 1) * $perPage;
    
    // 获取日志数据
	$logsQuery = $mysqli->query("
	    SELECT SQL_CALC_FOUND_ROWS 
	        al.id,
	        al.admin_id,
	        al.action,
	        al.target_table,
	        al.target_id,
	        al.details,
	        INET_NTOA(al.ip_address) AS ip_address,
	        al.user_agent,
	        al.created_at,
	        a.username
	    FROM ".DB_PREFIX."admin_logs al
	    LEFT JOIN ".DB_PREFIX."admins a ON al.admin_id = a.id
	    WHERE $whereClause
	    ORDER BY created_at DESC
	    LIMIT $perPage OFFSET $offset
	");
    
    $logs = $logsQuery->fetch_all(MYSQLI_ASSOC);
    
    // 获取总记录数
    $total = $mysqli->query("SELECT FOUND_ROWS()")->fetch_row()[0];
    $totalPages = ceil($total / $perPage);
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>管理后台 - 蓝宝石留言本</title>
    <link rel="icon" href="../assets/image/favicon.ico" type="image/ico">
    <link href="../assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css">
    <style>
        body {
            background-color: #f8f9fa;
            padding: 2rem 0;
        }

		.container-fluid {
		    max-width: 1400px !important;
		    margin: 0 auto !important;
		    background: white !important;
		    border-radius: 1rem !important;
		    box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1) !important;
		    overflow: hidden !important;
		}

        .header {
            background-color: #0d6efd;
            color: white;
            padding: 2rem;
            border-radius: 0 0 1rem 1rem;
        }

        .content {
            padding: 2rem;
        }

        .btn-primary {
            background-color: #0d6efd;
            border-color: #0d6efd;
        }

        .message-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 2rem;
        }

        .message-table th,
        .message-table td {
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }

        .message-table th {
            background-color: #f8f9fa;
        }

        .stat-card {
            transition: transform 0.2s;
            border: none;
            border-radius: 15px;
        }

        .stat-card:hover {
            transform: translateY(-5px);
        }

        .log-table {
            font-size: 0.9em;
        }

        .password-strength {
            height: 4px;
            width: 25%;
            transition: all 0.3s ease;
        }

        .admin-nav {
            background: #f8f9fa;
            box-shadow: 0 2px 4px rgba(0,0,0,.1);
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
        }

        .main-content {
            margin-top: 70px;
            padding: 20px;
        }

        .nav-link.active {
            color: #0d6efd !important;
            border-bottom: 2px solid #0d6efd;
        }

        .message-content {
            background: #f8f9fa;
            border-radius: 5px;
            padding: 1rem;
            margin-top: 1rem;
            max-height: 60vh;
            overflow-y: auto;
        }

        .table-hover tbody tr {
            cursor: pointer;
        }

        .filter-bar {
            background: #f8f9fa;
            padding: 1rem;
            border-radius: 8px;
            margin-bottom: 1.5rem;
        }

        .filter-nav .nav-link {
            border: 1px solid #dee2e6;
            margin: 0 5px;
            border-radius: 20px;
        }

        .filter-nav .nav-link.active {
            background: #0d6efd;
            color: white !important;
            border-color: #0d6efd;
        }
    </style>
</head>
<body class="bg-light">
    <div class="container-fluid">
        <div class="row">
            <div class="col">
                <!-- 顶部导航 -->
                <nav class="admin-nav navbar navbar-expand-lg navbar-light">
                    <div class="container-fluid">
                        <a class="navbar-brand" href="#">留言本管理</a>
                        <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#adminNav">
                            <span class="navbar-toggler-icon"></span>
                        </button>
                        <div class="collapse navbar-collapse" id="adminNav">
                            <ul class="navbar-nav me-auto mb-2 mb-lg-0">
                                <li class="nav-item">
                                    <a class="nav-link <?= $action === 'messages' ? 'active' : '' ?>" 
                                       href="?action=messages">
                                       <i class="bi bi-chat-left-text"></i> 留言管理
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link <?= $action === 'categories' ? 'active' : '' ?>" 
                                       href="?action=categories">
                                       <i class="bi bi-tags"></i> 分类管理
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link <?= $action === 'logs' ? 'active' : '' ?>" 
                                       href="?action=logs">
                                       <i class="bi bi-clock-history"></i> 操作日志
                                    </a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link <?= $action === 'config' ? 'active' : '' ?>" 
                                       href="?action=config">
                                       <i class="bi bi-gear"></i> 系统配置
                                    </a>
                                </li>
                            </ul>
                            <div class="d-flex">
                                <a href="logout.php" class="btn btn-outline-danger btn-sm">
                                    <i class="bi bi-box-arrow-right"></i> 退出系统
                                </a>
                            </div>
                        </div>
                    </div>
                </nav>

                <div class="main-content">
                    <?php if (isset($_SESSION['error'])): ?>
                    <div class="alert alert-danger alert-dismissible fade show">
                        <?= $_SESSION['error'] ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                    <?php unset($_SESSION['error']); endif; ?>

                    <?php if (isset($_SESSION['success'])): ?>
                    <div class="alert alert-success alert-dismissible fade show">
                        <?= $_SESSION['success'] ?>
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    </div>
                    <?php unset($_SESSION['success']); endif; ?>

                    <!-- 统计卡片 -->
                    <div class="row row-cols-1 row-cols-md-3 g-4 mb-4">
                        <div class="col">
                            <div class="card stat-card border-primary" onclick="location.href='?action=messages'" style="cursor: pointer;">
                                <div class="card-body">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-chat-text fs-1 text-primary me-3"></i>
                                        <div>
                                            <h5 class="card-title">📋 总留言数</h5>
                                            <p class="display-5 mb-0"><?= $stats['total'] ?? 0 ?></p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col">
                            <div class="card stat-card border-warning" onclick="location.href='?action=messages&filter=secret'" style="cursor: pointer;">
                                <div class="card-body">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-shield-lock fs-1 text-warning me-3"></i>
                                        <div>
                                            <h5 class="card-title">悄悄话</h5>
                                            <p class="display-5 mb-0"><?= $stats['secrets'] ?? 0 ?></p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="col">
                            <div class="card stat-card border-danger" onclick="location.href='?action=messages&filter=pending'" style="cursor: pointer;">
                                <div class="card-body">
                                    <div class="d-flex align-items-center">
                                        <i class="bi bi-clock-history fs-1 text-danger me-3"></i>
                                        <div>
                                            <h5 class="card-title">⏳ 待审核</h5>
                                            <p class="display-5 mb-0"><?= $stats['pending'] ?? 0 ?></p>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <?php switch ($action):
                        case 'categories': ?>
                                <!-- 分类管理模块 -->
                                <div class="card shadow mb-4">
                                    <div class="card-header bg-info text-white">
                                        <h5 class="mb-0"><i class="bi bi-tags"></i> 分类管理</h5>
                                    </div>
                                    <div class="card-body">
                                        <form method="post" class="mb-4">
                                            <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                            <div class="row g-3 align-items-center">
                                                <div class="col-md-8">
                                                    <input type="text" class="form-control" name="name" 
                                                        placeholder="输入新分类名称" required>
                                                </div>
                                                <div class="col-md-4">
                                                    <button type="submit" name="category_action" value="add" 
                                                        class="btn btn-success w-100">
                                                        <i class="bi bi-plus-circle"></i> 添加分类
                                                    </button>
                                                </div>
                                            </div>
                                        </form>

                                        <div class="table-responsive">
                                            <table class="table table-hover align-middle">
                                                <thead class="table-light">
                                                    <tr>
                                                        <th width="15%">ID</th>
                                                        <th width="55%">分类名称</th>
                                                        <th width="30%">操作</th>
                                                    </tr>
                                                </thead>
                                                <tbody>
                                                    <?php foreach ($categories as $cat): ?>
                                                    <tr>
                                                        <td><?= $cat['id'] ?></td>
                                                        <td><?= sanitizeInput($cat['typename']) ?></td>
                                                        <td>
                                                            <div class="btn-group">
                                                                <button class="btn btn-sm btn-warning" 
                                                                    data-bs-toggle="modal" 
                                                                    data-bs-target="#editModal<?= $cat['id'] ?>">
                                                                    <i class="bi bi-pencil"></i> 编辑
                                                                </button>
                                                                <form method="post" class="d-inline">
                                                                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                                    <input type="hidden" name="category_id" value="<?= $cat['id'] ?>">
                                                                    <button type="submit" name="category_action" value="delete" 
                                                                        class="btn btn-sm btn-danger" 
                                                                        onclick="return confirm('确定删除该分类？')">
                                                                        <i class="bi bi-trash"></i> 删除
                                                                    </button>
                                                                </form>
                                                            </div>

                                                            <!-- 编辑模态框 -->
                                                            <div class="modal fade" id="editModal<?= $cat['id'] ?>" tabindex="-1">
                                                                <div class="modal-dialog">
                                                                    <div class="modal-content">
                                                                        <form method="post">
                                                                            <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                                            <input type="hidden" name="category_id" value="<?= $cat['id'] ?>">
                                                                            <div class="modal-header">
                                                                                <h5 class="modal-title">编辑分类</h5>
                                                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                                            </div>
                                                                            <div class="modal-body">
                                                                                <input type="text" class="form-control" 
                                                                                    name="name" value="<?= sanitizeInput($cat['typename']) ?>" required>
                                                                            </div>
                                                                            <div class="modal-footer">
                                                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                                                                <button type="submit" name="category_action" value="edit" class="btn btn-primary">保存</button>
                                                                            </div>
                                                                        </form>
                                                                    </div>
                                                                </div>
                                                            </div>
                                                        </td>
                                                    </tr>
                                                    <?php endforeach; ?>
                                                </tbody>
                                            </table>
                                        </div>
                                    </div>
                                </div>

                        <?php break; case 'messages': ?>
                        <!-- 增强版留言管理 -->
                        <div class="card shadow">
                            <div class="card-header bg-primary text-white">
                                <h5 class="mb-0"><i class="bi bi-chat-left-text"></i> 留言管理</h5>
                            </div>
                            <div class="card-body">
					<!-- 增强的批量操作 -->
					<form method="post" class="mb-4" onsubmit="return confirm('确认执行批量操作？')">
					    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
					    <div class="row g-3 align-items-center">
					        <div class="col-md-4">
					            <select class="form-select" name="action" required>
					                <option value="">批量操作</option>
					                <option value="delete">删除选中</option>
					                <option value="approve">批量通过</option>
					                <option value="unapprove">设置为未审核</option>
					            </select>
					        </div>
					        <div class="col-md-8">
					            <button type="submit" class="btn btn-danger" name="bulk_action">
					                <i class="bi bi-lightning-charge"></i> 执行
					            </button>
					            <div class="form-check form-check-inline ms-3">
					                <input class="form-check-input" type="checkbox" id="selectAll">
					                <label class="form-check-label">全选本页</label>
					            </div>
					        </div>
					    </div>
					</form>
                            <!-- 留言表格 -->
                            <div class="table-responsive">
                                <table class="table table-hover align-middle">
                                    <thead class="table-light">
                                        <tr>
                                            <th><input type="checkbox" id="selectAllCheckbox"></th>
                                            <th>ID</th>
                                            <th>标题</th>
                                            <th>内容预览</th>
                                            <th>状态</th>
                                            <th width="15%">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                     <?php foreach ($messages as $msg): ?>
							    <tr data-bs-target="#detailModal<?= $msg['id'] ?>">
							        <td onclick="event.stopPropagation()">
							            <input type="checkbox" name="message_ids[]" value="<?= $msg['id'] ?>">
							        </td>
							        <td><?= $msg['id'] ?></td>
							        <td><?= sanitizeInput($msg['thetitle']) ?></td>
							        <td class="text-truncate" style="max-width: 200px;">
							            <?= sanitizeInput(substr($msg['thecontent'] ?? '', 0, 50)) ?>...
							            <button class="btn btn-sm btn-info ms-2" 
							                    data-bs-toggle="modal" 
							                    data-bs-target="#detailModal<?= $msg['id'] ?>">
							                <i class="bi bi-eye"></i> 查看完整
							            </button>
							        </td>
							        <td>
							            <form method="post" class="d-inline" onclick="event.stopPropagation()">
							                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
							                <input type="hidden" name="message_id" value="<?= $msg['id'] ?>">
							                <select name="shenhe" class="form-select form-select-sm" 
							                        onchange="if(confirm('确认修改审核状态？')){this.form.submit()}">
							                    <option value="0" <?= !$msg['shenhe'] ? 'selected' : '' ?>>待审核</option>
							                    <option value="1" <?= $msg['shenhe'] ? 'selected' : '' ?>>已审核</option>
							                </select>
							            </form>
							            <?php if ($msg['qiaoqiao']): ?>
							            <span class="badge bg-danger ms-2">悄悄话</span>
							            <?php endif; ?>
							        </td>
							        <td onclick="event.stopPropagation()">
							            <div class="btn-group">
							                <!-- 查看详情 -->
							                <button class="btn btn-sm btn-info me-1" 
							                        data-bs-toggle="modal" 
							                        data-bs-target="#detailModal<?= $msg['id'] ?>"
							                        title="查看详情">
							                    <i class="bi bi-eye"></i>
							                </button>
							
							                <!-- 编辑 -->
							                <button class="btn btn-sm btn-warning me-1" 
							                        data-bs-toggle="modal" 
							                        data-bs-target="#editModal<?= $msg['id'] ?>"
							                        title="编辑">
							                    <i class="bi bi-pencil"></i>
							                </button>
							
							                <!-- 回复 -->
							                <button class="btn btn-sm btn-primary me-1" 
							                        data-bs-toggle="modal" 
							                        data-bs-target="#replyModal<?= $msg['id'] ?>"
							                        title="回复">
							                    <i class="bi bi-reply"></i>
							                </button>
							
							                <!-- 删除 -->
							                <form method="post" onsubmit="return confirm('确认删除该留言？')">
							                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
							                    <input type="hidden" name="message_id" value="<?= $msg['id'] ?>">
							                    <input type="hidden" name="action" value="delete">
							                    <button type="submit" class="btn btn-sm btn-danger" title="删除">
							                        <i class="bi bi-trash"></i>
							                    </button>
							                </form>
							            </div>
							        </td>
							    </tr>
                                        <!-- 回复模态框 -->
                                        <div class="modal fade" id="replyModal<?= $msg['id'] ?>">
                                            <div class="modal-dialog">
                                                <div class="modal-content">
                                                    <form method="post">
                                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                        <input type="hidden" name="message_id" value="<?= $msg['id'] ?>">
                                                        <input type="hidden" name="action" value="reply">
                                                        <div class="modal-header">
                                                            <h5 class="modal-title"><i class="bi bi-reply"></i> 回复留言 #<?= $msg['id'] ?></h5>
                                                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                        </div>
                                                        <div class="modal-body">
                                                            <div class="mb-3">
                                                                <label class="form-label">回复内容</label>
                                                                <textarea class="form-control" name="reply_content" rows="4" required
                                                                          placeholder="请输入管理员回复内容"><?= sanitizeInput($msg['reply'] ?? '') ?></textarea>
                                                            </div>
                                                        </div>
                                                        <div class="modal-footer">
                                                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
                                                            <button type="submit" class="btn btn-primary">提交回复</button>
                                                        </div>
                                                    </form>
                                                </div>
                                            </div>
                                        </div>
                                        <!-- 详情模态框 -->
                                        <div class="modal fade" id="detailModal<?= $msg['id'] ?>">
                                            <div class="modal-dialog modal-lg">
                                                <div class="modal-content">
                                                    <div class="modal-header">
                                                        <h5 class="modal-title"><i class="bi bi-eye"></i>留言详情</h5>
                                                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                    </div>
                                                    <div class="modal-body">
                                                        <div class="row mb-3">
                                                            <div class="col-md-6">
                                                                <small class="text-muted">留言ID：<?= $msg['id'] ?></small>
                                                                <br>
                                                                <small class="text-muted">时间：<?= $msg['time'] ?></small>
                                                                <br>
                                                                <small class="text-muted">IP：<?= $msg['ip'] ?></small>
                                                                <br>
                                                                <small class="text-muted">IP 实际：<?= $msg['ipshiji'] ?></small>
                                                            </div>
                                                            <div class="col-md-6 text-end">
                                                                <?php if ($msg['qiaoqiao']): ?>
                                                                <span class="badge bg-danger">悄悄话</span>
                                                                <?php endif; ?>
                                                                <span class="badge bg-<?= $msg['shenhe'] ? 'success' : 'warning' ?>">
                                                                    <?= $msg['shenhe'] ? '已发布' : '待审核' ?>
                                                                </span>
                                                            </div>
                                                        </div>
                                                        <div class="message-content">
                                                            <h5><strong>标题：</strong><?= sanitizeInput($msg['thetitle']) ?></h5>
                                                            <hr>
                                                            <p><strong>昵称：</strong> <?= sanitizeInput($msg['nicheng']) ?></p>
                                                            <p><strong>内容：</strong></p>
                                                            <?= nl2br($msg['content']) ?>
                                                            <?php if (!empty($msg['reply'])): ?>
                                                            <div class="mt-4 p-3 bg-light rounded">
                                                                <h6><i class="bi bi-chat-square-text"></i> 管理员回复</h6>
                                                                <p><?= nl2br(sanitizeInput($msg['reply'])) ?></p>
                                                                <small class="text-muted">回复时间：<?= $msg['replytime'] ?></small>
                                                            </div>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                    <div class="modal-footer">
                                                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
							<!-- 编辑模态框 -->
							<div class="modal fade" id="editModal<?= $msg['id'] ?>">
							    <div class="modal-dialog modal-lg">
							        <div class="modal-content">
							            <form method="post">
							                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
							                <input type="hidden" name="message_id" value="<?= $msg['id'] ?>">
							                <input type="hidden" name="action" value="edit">
							                <div class="modal-header">
							                    <h5 class="modal-title">编辑留言</h5>
							                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
							                </div>
							                <div class="modal-body">
							                    <div class="mb-3">
							                        <label class="form-label">标题</label>
							                        <input type="text" class="form-control" 
							                               name="thetitle" value="<?= sanitizeInput($msg['thetitle']) ?>" required>
							                    </div>
							                    <div class="mb-3">
							                        <label class="form-label">昵称</label>
							                        <input type="text" class="form-control" 
							                               name="nicheng" value="<?= sanitizeInput($msg['nicheng']) ?>" required>
							                    </div>
							                    <div class="mb-3">
							                        <label class="form-label">内容</label>
							                        <textarea class="form-control" name="content" 
          rows="5" required><?= htmlspecialchars($msg['content'] ?? '', ENT_QUOTES, 'UTF-8') ?></textarea>
							                    </div>
							                    <div class="row">
							                        <div class="col-md-6">
							                            <div class="form-check form-switch">
							                                <input class="form-check-input" type="checkbox" 
							                                       name="qiaoqiao" id="qiaoqiao<?= $msg['id'] ?>" 
							                                       value="1" <?= $msg['qiaoqiao'] ? 'checked' : '' ?>>
							                                <label class="form-check-label" for="qiaoqiao<?= $msg['id'] ?>">
							                                    悄悄话模式
							                                </label>
							                            </div>
							                        </div>
							                        <div class="col-md-6">
							                            <div class="form-check form-switch">
							                                <input class="form-check-input" type="checkbox" 
							                                       name="shenhe" id="shenhe<?= $msg['id'] ?>" 
							                                       value="1" <?= $msg['shenhe'] ? 'checked' : '' ?>>
							                                <label class="form-check-label" for="shenhe<?= $msg['id'] ?>">
							                                    审核通过
							                                </label>
							                            </div>
							                        </div>
							                    </div>
							                </div>
							                <div class="modal-footer">
							                    <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
							                    <button type="submit" class="btn btn-primary">保存修改</button>
							                </div>
							            </form>
							        </div>
							    </div>
							</div>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                                <!-- 分页导航 -->
                                <nav class="mt-4">
                                    <ul class="pagination justify-content-center">
                                        <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                                        <li class="page-item <?= $i == $currentPage ? 'active' : '' ?>">
                                            <a class="page-link" 
                                               href="?action=messages&page=<?= $i ?><?= $filter ? '&filter='.$filter : '' ?>">
                                               <?= $i ?>
                                            </a>
                                        </li>
                                        <?php endfor; ?>
                                    </ul>
                                </nav>
                            </div>
                        </div>
                    <?php break; case 'config': ?> 
                    <!-- 配置和备份管理 -->
                    <div class="card shadow">
                        <div class="card-header bg-info text-white">
                            <h5 class="mb-0"><i class="bi bi-gear"></i> 系统配置管理</h5>
                        </div>
                        <div class="card-body">
                            <ul class="nav nav-tabs mb-4">
                                <li class="nav-item">
                                    <a class="nav-link <?= ($_GET['sub'] ?? '') === 'backup' ? '' : 'active' ?>" 
                                       href="?action=config">首页内容配置</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link <?= ($_GET['sub'] ?? '') === 'backup' ? '' : 'active' ?>" 
                                       href="?action=config&sub=tutorial">首页内容修改教程</a>
                                </li>
                                <li class="nav-item">
                                    <a class="nav-link <?= ($_GET['sub'] ?? '') === 'backup' ? 'active' : '' ?>" 
                                       href="?action=config&sub=backup">数据备份</a>
                                </li>
                            </ul>

                            <?php if(($_GET['sub'] ?? '') === 'tutorial'): ?>
                            <!-- 使用教程内容 -->
                            <div class="tutorial-content">
                                <div class="tutorial-text">
                                    <?php
                                    $tutorialFilePath = __DIR__ . '/../include/tutorial.php'; // 使用教程文件路径
                                    if (file_exists($tutorialFilePath)) {
                                        $tutorialContent = file_get_contents($tutorialFilePath);
                                        echo '<pre>' . htmlspecialchars($tutorialContent) . '</pre>';
                                    } else {
                                        echo '<p class="text-danger">教程文件不存在，请检查路径！</p>';
                                    }
                                    ?>
                                </div>
                            </div>
                            <?php elseif(($_GET['sub'] ?? '') !== 'backup'): ?>
                            <!-- 配置内容 -->
                            <form method="post">
                                <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                <input type="hidden" name="action" value="save_config">
                                <input type="hidden" name="config_type" value="content">
                                
                                <div class="mb-3">
                                    <label class="form-label">首页文本内容配置（JSON格式）</label>
                                    <textarea class="form-control font-monospace" 
                                              name="config_content" 
                                              rows="20"
                                              style="font-size: 0.9em"><?= 
                                          htmlspecialchars(
                                              file_get_contents($contentJsonPath),
                                              ENT_QUOTES
                                          ) 
                                      ?></textarea>
                                </div>
                                <button type="submit" class="btn btn-primary">
                                    <i class="bi bi-save"></i> 保存配置
                                </button>
                                <small class="text-muted ms-2">
                                    最后修改时间：<?= date('Y-m-d H:i:s', filemtime($contentJsonPath)) ?>
                                </small>
                            </form>
                            <?php else: ?>
                            <!-- 数据备份管理 -->
                            <div class="row">
                                <div class="col-md-6">
                                    <form method="post" class="mb-4">
                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                        <input type="hidden" name="action" value="create_backup">
                                        <button type="submit" class="btn btn-success">
                                            <i class="bi bi-database-down"></i> 创建新备份
                                        </button>
                                    </form>
                                </div>
                                <div class="col-md-6 text-end">
                                    <?php
                                    $backupDir = __DIR__.'/../backups/';
                                    $backups = glob($backupDir.'*.sql');
                                    rsort($backups);
                                    ?>
                                    <p>现有备份：<?= count($backups) ?> 个</p>
                                </div>
                            </div>

                            <div class="table-responsive">
                                <table class="table table-hover">
                                    <thead>
                                        <tr>
                                            <th>文件名</th>
                                            <th>大小</th>
                                            <th>时间</th>
                                            <th>操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach($backups as $file): ?>
                                        <tr>
                                            <td><?= basename($file) ?></td>
                                            <td><?= round(filesize($file)/1024, 2) ?> KB</td>
                                            <td><?= date('Y-m-d H:i:s', filemtime($file)) ?></td>
                                            <td>
                                                <a href="download_backup.php?file=<?= urlencode(basename($file)) ?>" 
                                                   class="btn btn-sm btn-primary me-1">
                                                    <i class="bi bi-download"></i>
                                                </a>
                                                <form method="post" class="d-inline">
                                                    <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                                    <input type="hidden" name="action" value="delete_backup">
                                                    <input type="hidden" name="filename" value="<?= basename($file) ?>">
                                                    <button type="submit" class="btn btn-sm btn-danger" 
                                                        onclick="return confirm('确定删除此备份？')">
                                                        <i class="bi bi-trash"></i>
                                                    </button>
                                                </form>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>
                            <?php endif; ?>
                        </div>
                    </div>
                    <?php break; case 'logs': ?>
                    <!-- 操作日志模块 -->
                    <div class="card shadow">
                        <div class="card-header bg-secondary text-white">
                            <h5 class="mb-0 d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-clock-history"></i> 操作日志</span>
                                <div class="d-flex">
                                    <!-- 导出日志按钮 -->
                                    <form method="post" action="export_logs.php" class="me-2">
                                        <input type="hidden" name="csrf_token" value="<?= generateCSRFToken() ?>">
                                        <button type="submit" class="btn btn-sm btn-success">
                                            <i class="bi bi-download"></i> 导出日志
                                        </button>
                                    </form>
                                </div>
                            </h5>
                        </div>
                        <div class="card-body">
                            <!-- 筛选表单 -->
                            <form method="get" class="row g-3 align-items-end mb-4">
                                <input type="hidden" name="action" value="logs">
                                <div class="col-md-3">
                                    <label class="form-label">操作类型</label>
                                    <select class="form-control" name="filter_type">
                                        <option value="">全部类型</option>
                                        <option value="login" <?= $filterType === 'login' ? 'selected' : '' ?>>登录</option>
                                        <option value="logout" <?= $filterType === 'logout' ? 'selected' : '' ?>>退出</option>
                                        <option value="message_edit" <?= $filterType === 'message_edit' ? 'selected' : '' ?>>编辑留言</option>
                                        <option value="message_delete" <?= $filterType === 'message_delete' ? 'selected' : '' ?>>删除留言</option>
                                        <option value="category_add" <?= $filterType === 'category_add' ? 'selected' : '' ?>>添加分类</option>
                                        <option value="category_edit" <?= $filterType === 'category_edit' ? 'selected' : '' ?>>编辑分类</option>
                                        <option value="category_delete" <?= $filterType === 'category_delete' ? 'selected' : '' ?>>删除分类</option>
                                        <option value="config_save" <?= $filterType === 'config_save' ? 'selected' : '' ?>>保存配置</option>
                                    </select>
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">管理员</label>
                                    <input type="text" class="form-control" name="filter_admin" 
                                           value="<?= htmlspecialchars($filterAdmin) ?>" 
                                           placeholder="输入管理员用户名">
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">开始时间</label>
                                    <input type="datetime-local" class="form-control" name="filter_start" 
                                           value="<?= htmlspecialchars($filterStart) ?>">
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">结束时间</label>
                                    <input type="datetime-local" class="form-control" name="filter_end" 
                                           value="<?= htmlspecialchars($filterEnd) ?>">
                                </div>
                                <div class="col-md-3">
                                    <label class="form-label">&nbsp;</label>
                                    <button type="submit" class="btn btn-primary w-100">筛选</button>
                                </div>
                            </form>

                            <div class="table-responsive">
                                <table class="table log-table">
                                    <thead>
                                        <tr>
                                            <th width="20%">时间</th>
                                            <th width="15%">操作类型</th>
                                            <th width="15%">管理员</th>
                                            <th width="30%">详情</th>
                                            <th width="15%">IP地址</th>
                                            <th width="10%">操作</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <?php foreach ($logs as $log): ?>
                                        <tr>
                                            <td><?= date('Y-m-d H:i:s', strtotime($log['created_at'])) ?></td>
                                            <td><?= htmlspecialchars($log['action']) ?></td>
                                            <td><?= htmlspecialchars($log['username'] ?? '未知用户') ?></td>
                                            <td class="text-truncate" style="max-width: 300px;">
                                                <?= htmlspecialchars($log['details']) ?>
                                            </td>
                                            <td><?= $log['ip_address'] ?></td>
                                            <td>
                                                <!-- 查看详情按钮 -->
                                                <button class="btn btn-sm btn-info" 
                                                        data-bs-toggle="modal" 
                                                        data-bs-target="#logDetailModal<?= $log['id'] ?>">
                                                    <i class="bi bi-eye"></i>
                                                </button>

                                                <!-- 日志详情模态框 -->
                                                <div class="modal fade" id="logDetailModal<?= $log['id'] ?>">
                                                    <div class="modal-dialog">
                                                        <div class="modal-content">
                                                            <div class="modal-header">
                                                                <h5 class="modal-title">日志详情 #<?= $log['id'] ?></h5>
                                                                <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                                                            </div>
                                                            <div class="modal-body">
                                                                <div class="mb-3">
                                                                    <label class="form-label">操作类型</label>
                                                                    <p class="form-control-plaintext"><?= htmlspecialchars($log['action']) ?></p>
                                                                </div>
                                                                <div class="mb-3">
                                                                    <label class="form-label">管理员ID</label>
                                                                    <p class="form-control-plaintext"><?= $log['admin_id'] ?></p>
                                                                </div>
                                                                <div class="mb-3">
                                                                    <label class="form-label">管理员用户名</label>
                                                                    <p class="form-control-plaintext"><?= htmlspecialchars($log['username'] ?? '未知用户') ?></p>
                                                                </div>
                                                                <div class="mb-3">
                                                                    <label class="form-label">详情</label>
                                                                    <p class="form-control-plaintext"><?= htmlspecialchars($log['details']) ?></p>
                                                                </div>
													<div class="mb-3">
													    <label class="form-label">IP地址</label>
													    <p class="form-control-plaintext"><?= $log['ip_address'] ?></p>
													</div>
                                                                <div class="mb-3">
                                                                    <label class="form-label">时间</label>
                                                                    <p class="form-control-plaintext"><?= date('Y-m-d H:i:s', strtotime($log['created_at'])) ?></p>
                                                                </div>
                                                            </div>
                                                            <div class="modal-footer">
                                                                <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">关闭</button>
                                                            </div>
                                                        </div>
                                                    </div>
                                                </div>
                                            </td>
                                        </tr>
                                        <?php endforeach; ?>
                                    </tbody>
                                </table>
                            </div>

                            <!-- 分页导航 -->
                            <nav class="mt-4">
                                <ul class="pagination justify-content-center">
                                    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                                    <li class="page-item <?= $i == $currentPage ? 'active' : '' ?>">
                                        <a class="page-link" 
                                           href="?action=logs&page=<?= $i ?><?= $filter ? '&filter='.$filter : '' ?>">
                                           <?= $i ?>
                                        </a>
                                    </li>
                                    <?php endfor; ?>
                                </ul>
                            </nav>
                        </div>
                    </div>
                    <?php break; ?>
                <?php endswitch; ?>
            </div>
        </div>
    </div>

<?php include __DIR__ . '/../include/footer.php'; ?>
<script src="../assets/bootstrap-5.3.3/js/bootstrap.bundle.min.js"></script>
<script>
   // 全选功能
   document.getElementById('selectAll').addEventListener('change', function(e) {
       const checkboxes = document.querySelectorAll('[name="message_ids[]"]');
       checkboxes.forEach(checkbox => checkbox.checked = e.target.checked);
   });

   // 自动调整模态框内容高度
   document.querySelectorAll('.modal').forEach(modal => {
       modal.addEventListener('show.bs.modal', function() {
           const content = this.querySelector('.message-content');
           if(content) content.style.maxHeight = `${window.innerHeight * 0.6}px`;
       });
   });

   // 阻止表格行点击事件传播到复选框
   document.querySelectorAll('td input[type="checkbox"]').forEach(checkbox => {
       checkbox.addEventListener('click', e => e.stopPropagation());
   });
</script>
</body>
</html>

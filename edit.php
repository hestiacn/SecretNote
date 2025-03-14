<?php
// 启用严格错误报告
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// 安全头设置
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' https://cdn.tiny.cloud; frame-src https://player.bilibili.com https://www.youtube.com https://player.vimeo.com; img-src 'self' data: https://i0.hdslb.com");
header("Referrer-Policy: strict-origin-when-cross-origin");
define('IP_API', 'https://cn.apihz.cn/api/ip/chaapi.php?id=10002193&key=7e1f5d0b23db5803520f39f63c917368&ip= ');
// 会话管理
if (session_status() === PHP_SESSION_NONE) {
    session_start([
        'cookie_secure' => isset($_SERVER['HTTPS']),
        'cookie_httponly' => true,
        'cookie_samesite' => 'Strict'
    ]);
}

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
// HTMLPurifier配置
require_once __DIR__ . '/assets/htmlpurifier/library/HTMLPurifier.auto.php';

// 替换原有sanitizeHTML函数
function sanitizeHTML($input) {
    $config = HTMLPurifier_Config::createDefault();
    $config->set('HTML.Allowed', 'p,strong,em,u,h1,h2,h3,h4,h5,h6,img[src|alt|class|loading],a[href|title|target],div,span,br,hr,ul,ol,li,blockquote,pre,code,iframe[src|frameborder|scrolling|class|allowfullscreen|width|height|allow],video[controls|width|height|poster],source[src|type]');
    $config->set('HTML.TargetBlank', true);
    $config->set('HTML.SafeIframe', true);
    $config->set('URI.SafeIframeRegexp', '%^(https?:)?//(player\.bilibili\.com|www\.youtube\.com/embed/)%');
    $config->set('Attr.AllowedClasses', [
        'bilibili-iframe', 'youtube-iframe', 
        'image-wrapper', 'video-container', 
        'user-image', 'uploaded-image'
    ]);
    return (new HTMLPurifier($config))->purify($input);
}
// 数据库配置
define('CONFIG_FILE', __DIR__ . '/include/config.php'); 

if (!file_exists(CONFIG_FILE)) {
    die("<h1 style='color:red'>配置文件缺失，请检查安装！路径：".CONFIG_FILE."</h1>");
}
require_once(CONFIG_FILE);

// 验证常量是否定义
$requiredConstants = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME'];
foreach ($requiredConstants as $constant) {
    if (!defined($constant)) {
        die("<h1 style='color:red'>配置错误：常量 $constant 未定义！</h1>");
    }
}

// 数据库连接（增加错误处理）
try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        throw new RuntimeException("数据库连接失败: ".$mysqli->connect_error);
    }
    $mysqli->set_charset('utf8mb4');
} catch (Exception $e) {
    die("<div class='alert alert-danger'>数据库错误：".$e->getMessage()."</div>");
}

// 初始化变量
$tablePrefix = DB_PREFIX;
$csrfToken = generateCSRFToken();
$error = null;
$success = null;
// 在数据库连接后添加分类查询
$categories = $mysqli->query("SELECT * FROM {$tablePrefix}typeid ORDER BY id")->fetch_all(MYSQLI_ASSOC);

// 处理表单提交
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        $error = 'CSRF令牌验证失败';
    } else {
        // 字段初始化
        $ip = filter_var($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: '无效IP';
        $thetitle = sanitizeInput($_POST['thetitle'] ?? '');
        $nicheng = sanitizeInput($_POST['nicheng'] ?? '');
        $homepage = '';
	    if (!empty($_POST['homepage'])) {
	        $homepage = filter_var($_POST['homepage'], FILTER_SANITIZE_URL);
	        // 进一步验证URL格式
	        if (!filter_var($homepage, FILTER_VALIDATE_URL)) {
	            $error = '请输入有效的主页URL地址';
	        }
	    }
        $image = sanitizeInput($_POST['avatar'] ?? 'touxiang/default3/1.gif');
        // 调整处理顺序
	   $rawContent = $_POST['content'] ?? '';
	   $decodedContent = html_entity_decode($rawContent, ENT_QUOTES | ENT_HTML5, 'UTF-8');
	   $content = sanitizeHTML($decodedContent);
        $qiaoqiao = isset($_POST['qiaoqiao']) ? 1 : 0;
        $qiaoqiaopass = $_POST['qiaoqiaopass'] ?? '';

        // 验证逻辑
        $requiredFields = ['thetitle' => '标题', 'nicheng' => '昵称', 'content' => '内容'];
        foreach ($requiredFields as $field => $name) {
            if (empty($_POST[$field] ?? '')) {
                $error = "{$name}不能为空";
                break;
            }
        }
		// ip
		$ip = filter_var($_SERVER['HTTP_X_FORWARDED_FOR'] ?? $_SERVER['REMOTE_ADDR'] ?? '', FILTER_VALIDATE_IP) ?: '';
		$location = '未知地区';
		if ($ip) {
		    require_once __DIR__.'/include/ip.php';
		    $location = getIPLocation($ip);
		}
		// ==================== 违禁词检测模块 - 修正版 ====================
		define('BANNED_WORDS_FILE', __DIR__.'/words.b64');
		define('CACHE_DIR', __DIR__.'/cache');
		define('REGEX_CACHE', CACHE_DIR.'/regex_cache.dat');
		
		// 创建缓存目录
		if (!file_exists(CACHE_DIR)) {
		    mkdir(CACHE_DIR, 0755, true);
		}
		
		// 加载违禁词库（支持base64编码）
		function loadBannedWords() {
		    if (!file_exists(BANNED_WORDS_FILE)) return [];
		    
		    $content = base64_decode(file_get_contents(BANNED_WORDS_FILE));
			return array_filter(
			    explode("\n", $content),
			    function($word) {
			        $word = trim($word);
			        return !empty($word) && 
			               $word[0] !== '#' &&
			               mb_check_encoding($word, 'UTF-8');
			    }
			);
		}
		
		// 智能正则生成器（中文优化版）
		function buildSmartRegex($words) {
		    $chunks = array_chunk($words, 50);
		    $patterns = [];
		
		    foreach ($chunks as $chunk) {
			$escaped = array_map(function($word) {
			    // 新增编码检测和空值过滤
			    $word = trim($word);
			    if (empty($word)) return null;
			    
			    $detectedEncoding = mb_detect_encoding($word, ['UTF-8','GBK','GB2312','BIG5','ASCII'], true);
			    $sourceEncoding = $detectedEncoding ?: 'UTF-8';
			    $word = mb_convert_encoding($word, 'UTF-8', $sourceEncoding);
			    $cleanWord = preg_replace('/\p{C}+/u', '', $word) ?? '';
			    
			    return $cleanWord !== '' ? $cleanWord : null;
			}, $chunk);
			
			// 新增数组过滤
			$escaped = array_filter($escaped);
		
		        if (!empty($escaped)) {
				    $patterns[] = '/'.implode('|', $escaped).'/iu';
				}
		    }
		
		    return $patterns;
		}
		
		// 带调试的违禁词检测
		function detectBannedWords($text, $patterns) {
		    // 预处理文本（保留中文、字母、数字）
		    $cleanText = preg_replace('/[^\p{Han}a-zA-Z0-9]/u', '', $text);
		    
		    foreach ($patterns as $pattern) {
		        if (preg_match($pattern, $cleanText, $matches)) {
		            error_log("[违禁词告警] 匹配规则: $pattern");
		            error_log("[违禁词告警] 命中内容: ".$matches[0]);
		            return true;
		        }
		        }}
			// 主执行流程
			$bannedWords = loadBannedWords();
			if (file_exists(REGEX_CACHE) && (time()-filemtime(REGEX_CACHE)) < 3600) {
			    $patterns = unserialize(file_get_contents(REGEX_CACHE));
			} else {
			    $patterns = buildSmartRegex($bannedWords);
			    file_put_contents(REGEX_CACHE, serialize($patterns));
			    error_log("[系统通知] 已重建违禁词正则缓存，共".count($patterns)."组模式");
			}
			
			// 执行检测
			if (!$error && !empty($patterns)) {
			    $checkText = $thetitle . ' ' . $content;
				$detectResult = detectBannedWords($checkText, $patterns);
				if ($detectResult && $detectResult['found']) {
				    $error = '内容包含敏感信息，请调整后重新提交';
			        
			        // 调试模式日志
			        if (defined('DEBUG_MODE')) {
			            error_log("[调试信息] 触发文本: ".substr($checkText, 0, 200));
			            error_log("[调试信息] 预处理后: ".substr($detectResult['cleanText'], 0, 200));
			        }
			    }
			}
			// 在相似度检测代码块前添加以下内容
			// 步骤1：提取B站视频特征
			$bvid = null;
			if (preg_match('/bvid=([A-Za-z0-9]+)/i', $content, $matches)) {
			    $bvid = $matches[1];
			}
			
			// 步骤2：特殊处理包含视频的内容
			if ($bvid) {
			    // 2.1 检查24小时内是否已有相同视频
			    $stmt = $mysqli->prepare("SELECT COUNT(*) FROM {$tablePrefix}book 
			                             WHERE content LIKE CONCAT('%', ?, '%')
			                             AND time > NOW() - INTERVAL 24 HOUR");
			    $stmt->bind_param('s', $bvid);
			    $stmt->execute();
			    
			    if ($stmt->get_result()->fetch_row()[0] > 0) {
			        $error = "相同视频已在24小时内分享过，请添加更多原创描述";
			    }
			
			    // 2.2 预处理时保留视频标识但移除结构代码
			    $contentForCompare = preg_replace('/<iframe[^>]*bvid='.$bvid.'[^>]*>[^<]*<\/iframe>/i', 
			                                    '[视频ID:'.$bvid.']', 
			                                    $content);
			} else {
			    $contentForCompare = $content;
			}
			
			// 步骤3：修改预处理逻辑（原代码修改处）
			$inputContent = preg_replace('/[^\p{Han}a-zA-Z0-9\/:%?&=._#-]/u', '', $contentForCompare);
			$inputContent = mb_strtolower($inputContent);
		// ==================== 危险模式检测 ====================
		$dangerousPatterns = [
		    '/<\s*script\b[^>]*>.*?<\/script>/is' => 'JavaScript脚本',
		    '/\bon\w+\s*=\s*["\'].*?["\']/i' => '事件处理器',
		    '/\b(union\s+select|select\b.*?\bfrom|insert\s+into|delete\s+from)\b/is' => 'SQL注入',
		    '/\b(eval|alert|prompt|confirm)\s*\(/i' => '危险函数'
		];
		
		foreach ($dangerousPatterns as $pattern => $type) {
		    if (preg_match($pattern, $content)) {
		        $error = "禁止包含{$type}信息";
		        break;
		    }
		}
		if (!$error) {
		    $similarThreshold = 75; 
		    $checkHours = 24;       
		    $stmt = $mysqli->prepare("SELECT content FROM {$tablePrefix}book 
		                            WHERE time > NOW() - INTERVAL ? HOUR
		                            ORDER BY id DESC LIMIT 100");
		    $stmt->bind_param('i', $checkHours);
		    $stmt->execute();
		    $result = $stmt->get_result();
		    
		    // 预处理输入内容
		    $inputContent = preg_replace('/[^\p{Han}a-z0-9]/u', '', $content);
		    $inputLength = mb_strlen($inputContent);
		    
		    while ($row = $result->fetch_assoc()) {
		        // 预处理数据库内容
		        $dbContent = preg_replace('/[^\p{Han}a-z0-9]/u', '', $row['content']);
		        $dbLength = mb_strlen($dbContent);
		        
		        // 长度差异过滤
		        if ($inputLength > 0 && abs($inputLength - $dbLength)/$inputLength > 0.3) {
		            continue;
		        }
		        
		        // 计算相似度
		        similar_text($inputContent, $dbContent, $percent);
		        if ($percent >= $similarThreshold) {
		            $error = "内容相似度过高（相似度".round($percent,1)."%），请修改后重试";
		            break;
		        }
		    }
		}
        if (!$error) {
            $stmt = $mysqli->prepare("SELECT COUNT(*) FROM {$tablePrefix}book WHERE ip = ? AND time > NOW() - INTERVAL 1 HOUR");
            $stmt->bind_param('s', $ip);
            $stmt->execute();
            $count = $stmt->get_result()->fetch_row()[0];
            if ($count >= 5) {
                $error = '提交过于频繁，请1小时后再试';
                file_put_contents(__DIR__.'/logs/security.log', 
                    "[".date('Y-m-d H:i:s')."] 频率限制 IP:{$ip}\n", FILE_APPEND);
            }
        }
        

        // 验证码验证
        if (!$error) {
            $captcha = $_POST['captcha'] ?? '';
            if (empty($captcha)) {
                $error = '验证码不能为空';
            } elseif (!isset($_SESSION['captcha']) || strtoupper($captcha) !== strtoupper($_SESSION['captcha'])) {
                $error = '验证码不正确';
                unset($_SESSION['captcha']);
            }
        }

		// 悄悄话密码验证
		if (!$error && $qiaoqiao && empty($qiaoqiaopass)) {
		  $error = '开启悄悄话必须设置密码';
		}
		// 修改原有密码处理部分
		if ($qiaoqiao) {
		    $qiaoqiaopass = trim($_POST['qiaoqiaopass'] ?? '');
		    
		    if (mb_strlen($qiaoqiaopass) < 4 || mb_strlen($qiaoqiaopass) > 16) {
		        $error = '密码长度需为4-16位';
		    }
		    
		    if (preg_match('/\s/', $qiaoqiaopass)) {
		        $error = '密码不能包含空格';
		    }
		    
		    // 密码复杂度要求
		    if (!preg_match('/^(?=.*\d)(?=.*[a-zA-Z]).+$/', $qiaoqiaopass)) {
		        $error = '密码需包含字母和数字';
		    }
		}
        // 数据库操作
        if (!$error) {
            $qiaoqiaopass = $qiaoqiao ? password_hash($qiaoqiaopass, PASSWORD_DEFAULT) : '';
            
            $stmt = $mysqli->prepare("INSERT INTO {$tablePrefix}book 
                (thetitle, nicheng, content, shenhe, ip, ipshiji, local_image, qiaoqiao, qiaoqiaopass, homepage) 
                VALUES (?, ?, ?, 1, ?, ?, ?, ?, ?, ?)");
                
            $stmt->bind_param('ssssssiss',
                $thetitle,
                $nicheng,
                $content,
                $ip,
                $location,
                $local_image,
                $qiaoqiao,
                $qiaoqiaopass,
                $homepage
            );

            if ($stmt->execute()) {
                $success = '留言添加成功';
            } else {
                $error = '数据库错误: ' . $stmt->error;
            }
        }
    }
}

?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>蓝宝石留言本 - 发布匿名留言</title>
    <link href="../assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="../assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css">
<style>
	/* 保证插入图片的包裹容器不影响编辑 */
	.image-wrapper {
	    margin: 1rem 0;
	    position: relative;
	}
	
	.image-wrapper + p {
	    margin-top: 1rem;
	}
   /* 新增编辑器相关样式 */
   .editor-toolbar {
       display: flex;
       gap: 8px;
       padding: 8px;
       background: #f8f9fa;
       border-bottom: 1px solid #dee2e6;
       flex-wrap: wrap;
   }
   .toolbar-btn {
       padding: 6px 10px;
       border: 1px solid #ddd;
       border-radius: 4px;
       cursor: pointer;
       background: white;
       transition: all 0.2s;
   }
   .toolbar-btn:hover {
       background-color: #e9ecef;
       border-color: #0d6efd;
       color: #0d6efd;
   }
   .emoji-panel {
       position: absolute;
       background: white;
       border: 1px solid #ddd;
       padding: 10px;
       border-radius: 4px;
       box-shadow: 0 2px 8px rgba(0,0,0,0.1);
       z-index: 1000;
       display: none;
       grid-template-columns: repeat(8, 1fr);
       gap: 5px;
       max-width: 300px;
   }
   .emoji-item {
       cursor: pointer;
       font-size: 20px;
       padding: 3px;
       text-align: center;
   }
   .image-upload-wrapper {
       position: relative;
       display: inline-block;
   }
   #imageInput {
       display: none;
   }
   #editor-container {
       min-height: 300px;
       padding: 15px;
       border: 1px solid #dee2e6;
       border-radius: 0 0 4px 4px;
       overflow-y: auto;
       outline: none;
   }
   .avatar-selector {
       grid-template-columns: repeat(6, 1fr);
       gap: 2px;
       margin: 15px 0;
   }
   .avatar-option {
       cursor: pointer;
       border: 2px solid transparent;
       border-radius: 5px;
       padding: 2px;
   }
   .avatar-option.selected {
       border-color: #0d6efd;
	  width: 60px; 
	  height: 60px; 
   }
   .container {
       max-width: 960px;
       margin: 0 auto;
       background: white;
       border-radius: 1rem;
       box-shadow: 0 0.5rem 1rem rgba(0, 0, 0, 0.1);
   }
   .header {
       background-color: #0d6efd;
       color: white;
       padding: 2rem;
       border-radius: 0 0 1rem 1rem;
   }  
.video-container iframe {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
}

.embed-video {
  max-width: 100%;
  height: auto;
}
.emoji-panel {
   display: none;
   position: absolute;
   top: 100%;
   left: 0;
}
.emoji-panel.active {
   display: grid;
}
.uploaded-image {
  margin: 1rem 0;
  text-align: center;
  border: 1px solid #dee2e6;
  padding: 10px;
}

.image-caption {
  font-size: 0.9em;
  color: #666;
  margin-top: 0.5rem;
}
/* 新增图片容器样式 */
.image-wrapper img {
    max-width: 100%;
    height: auto;
    border-radius: 4px;
    transition: opacity 0.3s ease;
}

.image-wrapper img[data-original] {
    cursor: zoom-in;
}
/* 新增预览模态框样式 */
#imagePreviewModal .modal-dialog {
    max-width: 90vw;
}

#previewImage {
    max-height: 80vh;
    object-fit: contain;
}
/* 修改为以下新样式 */
.uploaded-image {
    max-width: 100%;
    height: auto;
    margin: 0.5rem 0;
    border-radius: 4px;
    cursor: zoom-in;
    transition: opacity 0.3s ease;
}

.uploaded-image:hover {
    opacity: 0.9;
}
.media-container {
    border: 1px solid #dee2e6;
    border-radius: 4px;
    margin: 1rem 0;
    padding: 1rem;
    background: #f8f9fa;
}
.media-container img {
    max-width: 100%;
    height: auto;
    display: block;
    margin: 0 auto;
}
.media-caption {
    text-align: center;
    margin-top: 0.5rem;
    font-size: 0.9em;
    color: #666;
}
.image-wrapper {
  position: relative;
  display: inline-block;
}
.delete-btn {
  position: absolute;
  right: 5px;
  top: 5px;
  cursor: pointer;
  background: red;
  color: white;
  width: 20px;
  height: 20px;
  text-align: center;
  line-height: 18px;
  border-radius: 50%;
  display: none;
}
.image-wrapper:hover .delete-btn {
  display: block;
}
.video-container iframe,
.video-container video {
  position: absolute;
  top: 0;
  left: 0;
  width: 100%;
  height: 100%;
}

.embed-preview {
  margin-top: 1rem;
  min-height: 80px;
}
/* 图片预览模态框样式 */
#imagePreviewModal .modal-content {
  background: rgba(0,0,0,0.8);
  transition: transform 0.3s ease;
}

#imagePreviewModal .modal-body {
  padding: 0;
}

#previewImage {
  transition: transform 0.3s ease;
  object-fit: contain;
}

/* 移动端优化 */
@media (max-width: 768px) {
  #imagePreviewModal .modal-dialog {
    margin: 5px;
  }
  
  #previewImage {
    max-height: 80vh;
  }
}
/* 新增视频iframe样式 */
.video-iframe,
.bilibili-iframe {
    width: 100%;
    height: 400px;
    border: none;
    margin: 1rem 0;
    border-radius: 4px;
    background: #000;
}

/* 移除原有video-container样式 */
.video-container {
    display: none; /* 删除原有容器样式 */
}
</style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1 class="display-5 fw-bold mb-3">发布匿名留言</h1>
        </div>

        <div class="content p-4">
	    <!-- 新增消息提示 -->
	    <?php if ($error): ?>
	    <div class="alert alert-danger alert-dismissible fade show" role="alert">
	        <?= htmlspecialchars($error) ?>
	        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
	    </div>
	    <?php endif; ?>
	
	    <?php if ($success): ?>
	    <div class="alert alert-success alert-dismissible fade show" role="alert">
	        <?= htmlspecialchars($success) ?>
	        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
	    </div>
	    <?php endif; ?>
            <form method="post">
                <!-- 头像选择 -->
                <div class="mb-3">
                    <label class="form-label">选择头像</label>
                    <div class="avatar-selector">
                        <?php
                        $avatars = array_map(fn($n) => "assets/touxiang/default3/{$n}.gif", range(1, 24));
                        foreach ($avatars as $avatar):
                        ?>
                        <label class="avatar-option">
                            <input type="radio" name="avatar" value="<?= htmlspecialchars($avatar) ?>" 
                                   <?= $avatar === 'touxiang/default3/1.gif' ? 'checked' : '' ?> hidden>
                            <img src="../<?= htmlspecialchars($avatar) ?>" 
                                 class="img-thumbnail" 
                                 width="60" 
                                 alt="头像 <?= $avatar ?>">
                        </label>
                        <?php endforeach; ?>
                    </div>
                </div>
                 <!-- 新增主页输入框 -->
                <div class="mb-3">
                    <label class="form-label">个人主页</label>
                    <input type="url" 
                           class="form-control" 
                           name="homepage"
                           placeholder="https://example.com"
                           pattern="https?://.+">
                    <div class="form-text">请输入完整的http(s)://开头的主页地址</div>
                </div>
                <!-- 分类选择 -->
                <div class="mb-3">
                    <label class="form-label">选择分类</label>
                    <select class="form-select" name="typeid">
                        <option value="0">-- 无分类 --</option>
                        <?php foreach ($categories as $cat): ?>
                        <option value="<?= $cat['id'] ?>"><?= htmlspecialchars($cat['typename']) ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <!-- 表单字段 -->
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($csrfToken ?? '') ?>">
			<?php
			$fields = [
			    'thetitle' => ['label' => '标题', 'type' => 'text'],
			    'nicheng' => ['label' => '昵称（默认匿名）', 'type' => 'text']
			];
			foreach ($fields as $name => $config): ?>
			<div class="mb-3">
			    <label class="form-label"><?= htmlspecialchars($config['label']) ?></label>
			    <input type="<?= htmlspecialchars($config['type']) ?>" 
			           class="form-control" 
			           name="<?= htmlspecialchars($name) ?>"
			           value="<?= $name === 'nicheng' ? '匿名留言' : '' ?>"
			           <?= $name === 'thetitle' ? 'required' : '' ?>>
			</div>
			<?php endforeach; ?>

                <!-- 富文本编辑器 -->
                <div class="mb-3">
                    <label class="form-label">内容</label>
                    <div class="border rounded">
                        <div class="editor-toolbar">
                            <button type="button" class="toolbar-btn" data-command="bold" title="加粗">
                                <i class="bi bi-type-bold"></i>
                            </button>
                            <button type="button" class="toolbar-btn" data-command="italic" title="斜体">
                                <i class="bi bi-type-italic"></i>
                            </button>
                            <button type="button" class="toolbar-btn" data-command="underline" title="下划线">
                                <i class="bi bi-type-underline"></i>
                            </button>
                            <div class="image-upload-wrapper">
						<!-- 修改原图片上传按钮 -->
						<button type="button" class="toolbar-btn" 
						        data-action="insertImage" 
						        title="插入图片"
						        data-bs-toggle="modal" 
						        data-bs-target="#imageModal">
						  <i class="bi bi-image"></i>
						</button>
                            </div>
                            <div class="position-relative">
                                <button type="button" class="toolbar-btn" title="插入表情">
                                    <i class="bi bi-emoji-smile"></i>
                                </button>
                                <div class="emoji-panel">
                                    <?php
                                    $emojis = ['😀','😃','😄','😁','😆','😅','😂','🤣',
                                              '❤️','👍','🎉','🚀','😊','😎','🥳','🤩'];
                                    foreach ($emojis as $emoji): ?>
                                    <span class="emoji-item" data-emoji="<?= $emoji ?>"><?= $emoji ?></span>
                                    <?php endforeach; ?>
                                </div>
                            </div>
			             <!-- 新增视频嵌入按钮 -->
			            <button type="button" class="toolbar-btn" title="插入视频" data-bs-toggle="modal" data-bs-target="#videoModal">
			                <i class="bi bi-camera-reels"></i>
			            </button>
			            
			            <!-- 列表按钮 -->
			            <div class="btn-group">
			                <button type="button" class="toolbar-btn" title="无序列表" data-command="insertUnorderedList">
			                    <i class="bi bi-list-ul"></i>
			                </button>
			                <button type="button" class="toolbar-btn" title="有序列表" data-command="insertOrderedList">
			                    <i class="bi bi-list-ol"></i>
			                </button>
			            </div>
			           </div>
                        </div>
                        <div id="editor-container" 
                             contenteditable="true" 
                             data-placeholder="请输入内容..."
                             class="p-3"></div>
                    </div>
                    <textarea name="content" id="hidden-content" hidden></textarea>
                </div>

                <!-- 悄悄话设置 -->
                <div class="mb-3">
                    <div class="form-check">
                        <input class="form-check-input" 
                               type="checkbox" 
                               name="qiaoqiao" 
                               id="qiaoqiao">
                        <label class="form-check-label" for="qiaoqiao">启用悄悄话</label>
                    </div>
                    <input type="password" 
                           class="form-control mt-2" 
                           name="qiaoqiaopass" 
                           id="qiaoqiaopass" 
                           placeholder="设置查看密码"
                           disabled
                           required>
                </div>

                <!-- 验证码 -->
			<div class="mb-3 row align-items-center">
			    <div class="col-md-4">
			        <input type="text" 
			               class="form-control"
			               name="captcha"
			               placeholder="输入验证码"
			               required>
			    </div>
				<div class="col-md-4 mt-2 mt-md-0">
				    <img src="../include/captcha.php" 
				         alt="验证码" 
				         class="img-thumbnail"
				         onclick="this.src='../include/captcha.php?'+Date.now()"
				         id="captchaImg"
				         style="cursor: pointer; height: 40px;">
				</div>
			</div>

                <button type="submit" class="btn btn-primary w-100 py-2">
                    <i class="bi bi-send-check me-2"></i>提交留言
                </button>
            </form>
        </div>
    </div>
<!-- 图片上传模态框 -->
<div class="modal fade" id="imageModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">插入图片</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <!-- 选项卡导航 -->
        <ul class="nav nav-tabs mb-3">
          <li class="nav-item">
            <a class="nav-link active" href="#uploadTab" data-bs-toggle="tab">上传图片</a>
          </li>
          <li class="nav-item">
            <a class="nav-link" href="#urlTab" data-bs-toggle="tab">网络图片</a>
          </li>
        </ul>

        <!-- 选项卡内容 -->
        <div class="tab-content">
          <!-- 上传图片选项卡 -->
          <div class="tab-pane fade show active" id="uploadTab">
            <div class="mb-3">
              <label class="form-label">选择图片文件</label>
              <!-- 预览容器 -->
              <div id="uploadPreview" class="mb-2 border rounded p-2 text-center"></div>
              <input type="file" class="form-control" 
                     id="localImage" 
                     accept="image/jpeg, image/png, image/gif">
              <div class="form-text mt-2">支持的格式包括JPEG、PNG等常见图片类型，所有上传的图片将以更高效的webp格式进行展示！</div>
              
              <!-- 进度条 -->
              <div class="progress mt-3" style="display: none;">
                <div class="progress-bar progress-bar-striped" 
                     role="progressbar" 
                     style="width: 0%"
                     aria-valuenow="0" 
                     aria-valuemin="0" 
                     aria-valuemax="100">
                </div>
              </div>
            </div>
          </div>

          <!-- 网络图片选项卡 -->
          <div class="tab-pane fade" id="urlTab">
            <div class="mb-3">
              <label class="form-label">图片URL地址</label>
              <!-- 预览容器 -->
              <div id="urlPreview" class="mb-2 border rounded p-2 text-center"></div>
              <input type="url" class="form-control" 
                     id="imageUrl" 
                     placeholder="https://example.com/image.jpg">
              <div class="form-text mt-2">请输入合法的图片URL地址</div>
            </div>
          </div>
        </div>
      </div>
      
      <div class="modal-footer">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">取消</button>
        <button type="button" class="btn btn-primary" id="confirmImage">插入图片</button>
      </div>
    </div>
  </div>
</div>
<!-- 视频模态框结构 -->
<div class="modal fade" id="videoModal" tabindex="-1">
  <div class="modal-dialog">
    <div class="modal-content">
      <div class="modal-header">
        <h5 class="modal-title">插入视频</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div class="mb-3">
          <label class="form-label">视频地址</label>
          <input type="url" class="form-control" id="videoUrl" 
            placeholder="输入视频直链地址（MP4/WebM等）"
            required>
            <div class="form-text">
            示例：
            YouTube: https://youtu.be/abc123 <br>
            B站: https://www.bilibili.com/video/BV1xx411c7BF <br>
            MP4: https://example.com/video.mp4
          </div>
        </div>
      </div>
      <div class="modal-footer">
        <button type="button" class="btn btn-primary" onclick="insertVideo()">插入</button>
      </div>
    </div>
  </div>
</div>
<!-- 图片预览模态框 -->
<div class="modal fade" id="imagePreviewModal" tabindex="-1">
  <div class="modal-dialog modal-dialog-centered modal-xl">
    <div class="modal-content bg-transparent border-0">
      <div class="modal-body p-0 text-center">
        <img id="previewImage" 
             class="img-fluid rounded shadow-lg" 
             style="max-height: 90vh; cursor: zoom-out;">
        <button type="button" 
                class="btn btn-danger btn-sm position-absolute top-0 end-0 m-2" 
                data-bs-dismiss="modal">
          <i class="bi bi-x-lg"></i>
        </button>
      </div>
    </div>
  </div>
</div>
<script src="../assets/bootstrap-5.3.3/js/bootstrap.bundle.min.js"></script>
<script src="../assets/bootstrap-5.3.3/js/jquery.min.js"></script>
<script src="../assets/bootstrap-5.3.3/js/purify.min.js"></script>
<script>
// 全局变量定义
let lastSelection = null;
const editor = document.getElementById('editor-container');
const hiddenContent = document.getElementById('hidden-content');

// DOMContentLoaded 事件监听器
document.addEventListener('DOMContentLoaded', function() {
    // 初始化编辑器
    initEditor();
    
    // 图片模态框处理
    document.querySelector('[data-action="insertImage"]').addEventListener('click', function() {
        $('#imageModal').modal('show');
    });

    // 增强版图片上传功能
    document.getElementById('confirmImage').addEventListener('click', async function() {
        const btn = this;
        const activeTab = document.querySelector('.tab-pane.active');
        let imageHTML = '';

        try {
            // 准备工作
            btn.disabled = true;
            saveSelection();

            if (!lastSelection || !editor.contains(lastSelection.startContainer)) {
                const range = document.createRange();
                range.selectNodeContents(editor);
                range.collapse(false);
                lastSelection = range;
            }

            // 图片处理逻辑
            if (activeTab.id === 'uploadTab') {
                const file = document.getElementById('localImage').files[0];
                if (!file) throw new Error('请选择要上传的图片文件');

                // 显示上传进度
                const progressBar = document.querySelector('.progress-bar');
                const progressContainer = document.querySelector('.progress');
                progressContainer.style.display = 'block';

                const formData = new FormData();
                formData.append('image', file);
                formData.append('csrf_token', '<?= $csrfToken ?>');

                const response = await fetch('../include/upload.php', {
                    method: 'POST',
                    body: formData,
                    headers: {
                        'X-Requested-With': 'XMLHttpRequest'
                    }
                });

                if (!response.ok) throw new Error(`上传失败: ${response.statusText}`);
                const result = await response.json();
                if (result.errno !== 0) throw new Error(result.message);

                // 构造图片HTML
                imageHTML = `
                <div class="image-wrapper" contenteditable="false">
                  <img src="${result.data.url}" 
                       class="uploaded-image"
                       alt="用户上传图片"
                       loading="lazy"
                       data-original="${result.data.hd_url || result.data.url}"
                       data-zoom-src="${result.data.url}"
                       style="cursor: zoom-in;">
                </div>`;
            } else {
                const urlInput = document.getElementById('imageUrl');
                const url = urlInput.value.trim();
                if (!url) throw new Error('请输入图片URL地址');

                try {
                    new URL(url);
                } catch {
                    throw new Error('无效的URL格式');
                }

                imageHTML = `
                    <div class="image-wrapper" contenteditable="false">
                        <a href="${url}" target="_blank" rel="noopener noreferrer">
                            <img src="../include/proxy.php?url=${encodeURIComponent(url)}" 
                                 class="img-fluid" 
                                 alt="网络图片"
                                 loading="lazy"
                                 data-original="${url}">
                        </a>
                    </div>`;
            }

            // 插入编辑器
            restoreSelection();
            const cleanHTML = DOMPurify.sanitize(imageHTML, {
                ADD_TAGS: ['onload', 'onerror'],
                ADD_ATTR: ['contenteditable']
            });
            document.execCommand('insertHTML', false, cleanHTML);
            syncContent();
            $('#imageModal').modal('hide');
            
            // 插入图片后调整选区
            const insertedImg = editor.querySelector('img:last-child');
            if (insertedImg) {
                const range = document.createRange();
                const selection = window.getSelection();
                const nextSibling = insertedImg.parentElement.nextSibling;
                if (nextSibling && nextSibling.nodeName === 'BR') {
                    nextSibling.remove();
                }
                // 创建新段落并将光标定位到图片后面
                const newParagraph = document.createElement('p');
                newParagraph.innerHTML = '<br>';
                editor.appendChild(newParagraph);
                
                range.setStartAfter(newParagraph);
                range.collapse(true);
                
                selection.removeAllRanges();
                selection.addRange(range);
                editor.focus();
            }
        } catch (error) {
            console.error('图片操作失败:', error);
            const errorAlert = document.createElement('div');
            errorAlert.className = 'alert alert-danger mt-2';
            errorAlert.innerHTML = `
                <i class="bi bi-exclamation-triangle"></i>
                ${error.message}
            `;
            const modalBody = document.querySelector('#imageModal .modal-body');
            modalBody.appendChild(errorAlert);
            setTimeout(() => errorAlert.remove(), 3000);
        } finally {
            btn.disabled = false;
            const progressBar = document.querySelector('.progress-bar');
            const progressContainer = document.querySelector('.progress');
            progressBar.style.width = '0%';
            progressContainer.style.display = 'none';
            document.getElementById('localImage').value = '';
            document.getElementById('imageUrl').value = '';
            document.getElementById('uploadPreview').innerHTML = '';
            document.getElementById('urlPreview').innerHTML = '';
        }
    });

    // 头像选择功能
    document.querySelectorAll('.avatar-option').forEach(item => {
        item.addEventListener('click', function() {
            document.querySelectorAll('.avatar-option').forEach(el => {
                el.classList.remove('selected');
            });
            this.classList.add('selected');
            this.querySelector('input').checked = true;
        });
    });

    // 悄悄话功能
    document.getElementById('qiaoqiao').addEventListener('change', function() {
        const passInput = document.getElementById('qiaoqiaopass');
        passInput.disabled = !this.checked;
        passInput.required = this.checked;
    });

    // 表单提交验证
    document.querySelector('form').addEventListener('submit', function(e) {
        if (editor.textContent.trim().length < 10) {
            alert('内容不能少于10个字符');
            e.preventDefault();
        }
        /*const images = editor.querySelectorAll('img.uploaded-image');
        images.forEach(img => {
            if (img.naturalWidth > 1200 || img.naturalHeight > 800) {
                alert('图片尺寸过大，请调整后上传');
                e.preventDefault();
            }
        });*/
    });

   // Emoji功能
    document.querySelectorAll('.emoji-item').forEach(item => {
        item.addEventListener('click', function(e) {
            e.stopPropagation(); // 阻止事件冒泡
            const emoji = this.textContent;
            // 确保编辑器有焦点
            editor.focus();
            // 插入表情
            document.execCommand('insertText', false, emoji);
            syncContent(); // 同步内容
        });
    });

   // 显示/隐藏Emoji面板
   document.querySelector('[title="插入表情"]').addEventListener('click', function(e) {
       const panel = this.nextElementSibling;
       panel.style.display = panel.style.display === 'grid' ? 'none' : 'grid';
       e.stopPropagation();
   });

   // 点击外部关闭Emoji面板
   document.addEventListener('click', () => {
       document.querySelector('.emoji-panel').style.display = 'none';
   });

    const emojiBtn = document.querySelector('[data-command="insertEmoji"]');
    const emojiPanel = document.querySelector('.emoji-panel');
    emojiBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        emojiPanel.classList.toggle('active');
    });
    document.querySelectorAll('.emoji-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const emoji = e.target.dataset.emoji;
            document.execCommand('insertText', false, emoji);
            emojiPanel.classList.remove('active');
        });
    });
    document.addEventListener('click', () => {
        emojiPanel.classList.remove('active');
    });

    // 修复悄悄话功能
    const qiaoqiaoCheck = document.getElementById('qiaoqiao');
    const qiaoqiaoPass = document.getElementById('qiaoqiaopass');
    qiaoqiaoPass.disabled = !qiaoqiaoCheck.checked;
    qiaoqiaoCheck.addEventListener('change', () => {
        qiaoqiaoPass.disabled = !qiaoqiaoCheck.checked;
        qiaoqiaoPass.required = qiaoqiaoCheck.checked;
    });
});

// 同步内容到隐藏域
function syncContent() {
    // 清理规则
    let rawHTML = editor.innerHTML; 
    let cleanedHTML = rawHTML
        .replace(/<p>\s*<br\s?\/?>\s*<\/p>/gi, '')  // 移除空段落
        .replace(/(<br\s?\/?>){2,}/gi, '<br>')      // 合并多个换行
        .replace(/<p>\s*<\/p>/gi, '')               // 移除空白段落
        .replace(/<\/div>\s*<br>/gi, '</div>')      // 移除div后的换行
        .replace(/(<\/[^>]+>)\s*(<[^>/]+>)/g, '$1$2'); // 移除标签间空白
    // 强化净化规则
    hiddenContent.value = DOMPurify.sanitize(editor.innerHTML, {
        ALLOWED_TAGS: ['p','strong','em','u','h1','h2','h3','h4','h5','h6','img','a','div',
                      'span','br','hr','ul','ol','li','blockquote','pre','code','iframe',
                      'video','source','figure','figcaption'],
        ALLOWED_ATTR: ['src', 'alt', 'class', 'href', 'title', 'width', 'height', 
                      'data-*', 'loading', 'crossorigin', 'referrerpolicy',
                      'frameborder', 'scrolling', 'allowfullscreen', 'allow', 'target',
                      'controls', 'poster', 'type'],
        ADD_ATTR: ['loading', 'data-original', 'frameborder'],
        ADD_TAGS: ['iframe', 'video', 'source']
    });
}

// 选区管理
function saveSelection() {
    const sel = window.getSelection();
    if (sel.rangeCount > 0) {
        const range = sel.getRangeAt(0);
        if (editor.contains(range.startContainer)) {
            lastSelection = range;
        }
    }
}

function restoreSelection() {
    if (!lastSelection) return;
    
    try {
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(lastSelection);
        editor.focus();
    } catch (error) {
        console.error('选区恢复失败:', error);
        // 失败时定位到编辑器末尾
        const range = document.createRange();
        range.selectNodeContents(editor);
        range.collapse(false);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
        editor.focus();
    }
}

// 初始化编辑器
function initEditor() {
    // 初始化空内容结构
    editor.innerHTML = '<div><br></div>';
    
    // 输入事件监控
    editor.addEventListener('keydown', function(e) {
        // 拦截回车键
        if (e.key === 'Enter') {
            const sel = window.getSelection();
            if (sel.rangeCount > 0) {
                const range = sel.getRangeAt(0);
                // 检查当前是否在空段落中
                if (range.startContainer.parentElement.tagName === 'P' && 
                    range.startContainer.parentElement.innerHTML === '<br>') {
                    e.preventDefault();
                    document.execCommand('formatBlock', false, 'div');
                }
            }
        }
    });
    // 格式按钮功能
    document.querySelectorAll('[data-command]').forEach(btn => {
        btn.addEventListener('click', function(e) {
            e.preventDefault();
            saveSelection();
            
            const command = this.dataset.command;
            const value = this.dataset.insert || null;
            
            restoreSelection();
            editor.focus();
            
            try {
                if (command === 'insertHTML') {
                    document.execCommand('insertHTML', false, value);
                } else {
                    document.execCommand(command, false, value);
                }
                syncContent();
            } catch (error) {
                console.error('命令执行失败:', error);
            }
        });
    });

    // 自动同步
    editor.addEventListener('input', syncContent);
    editor.addEventListener('paste', syncContent);
    
    // 初始化内容
    editor.innerHTML = '<p><br></p>';
}

// 在编辑器点击时更新选区
editor.addEventListener('click', function() {
    saveSelection();
});

// 在编辑器输入时保持选区
editor.addEventListener('input', function() {
    saveSelection();
    syncContent();
});

// 在DOMContentLoaded事件监听器内添加
editor.addEventListener('click', function(e) {
  if (e.target.classList.contains('delete-btn')) {
    e.target.closest('.image-wrapper').remove();
    syncContent();
  }
});

// 允许键盘删除操作
editor.addEventListener('keydown', function(e) {
  if (e.key === 'Delete' || e.key === 'Backspace') {
    const selection = window.getSelection();
    if (selection.anchorNode.closest('.image-wrapper')) {
      selection.anchorNode.closest('.image-wrapper').remove();
      syncContent();
    }
  }
});

// 简化后的视频插入函数
function insertVideo() {
    try {
        saveSelection();
        
        const urlInput = document.getElementById('videoUrl');
        let url = urlInput.value.trim();
        if (!url) {
            alert('请输入视频地址');
            return;
        }

        // 自动补全协议头
        if (!/^https?:\/\//i.test(url)) {
            url = 'https://' + url;
        }

        let iframeText = '';
        try {
            const videoUrl = new URL(url);
            
            // YouTube视频
            if (videoUrl.hostname.replace('www.', '') === 'youtube.com' || 
                videoUrl.hostname === 'youtu.be') {
                const videoId = videoUrl.searchParams.get('v') || 
                              videoUrl.pathname.split('/').pop();
                
                iframeText = `<iframe src="https://www.youtube.com/embed/${videoId}" 
                    frameborder="0" 
                    allowfullscreen
                    allow="accelerometer; autoplay; encrypted-media; gyroscope; picture-in-picture"
                    class="video-iframe"></iframe>`;
            }
            // B站视频
            else if (videoUrl.hostname.includes('bilibili.com')) {
                const bvid = url.match(/(BV[\w]{10})/)?.[0];
                if (bvid) {
                    iframeText = `<iframe src="https://player.bilibili.com/player.html?bvid=${bvid}&page=1" 
                        frameborder="0" 
                        scrolling="no"
                        class="bilibili-iframe"></iframe>`;
                }
            }
            // 腾讯视频
            else if (videoUrl.hostname.includes('v.qq.com')) {
                const videoId = videoUrl.pathname.split('/').pop();
                iframeText = `<iframe src="https://v.qq.com/txp/vidembed/${videoId}" 
                    frameborder="0" 
                    allowfullscreen
                    class="tencent-iframe"></iframe>`;
            }
            // 优酷视频
            else if (videoUrl.hostname.includes('youku.com')) {
                const videoId = videoUrl.pathname.split('/').pop();
                iframeText = `<iframe src="https://player.youku.com/embed/${videoId}" 
                    frameborder="0" 
                    allowfullscreen
                    class="youku-iframe"></iframe>`;
            }
            // Vimeo视频
            else if (videoUrl.hostname.includes('vimeo.com')) {
                const videoId = videoUrl.pathname.split('/').pop();
                iframeText = `<iframe src="https://player.vimeo.com/video/${videoId}" 
                    frameborder="0" 
                    allowfullscreen
                    class="vimeo-iframe"></iframe>`;
            }
            // 通用视频文件
            else if (/\.(mp4|webm|ogg)$/i.test(url)) {
                iframeText = `<video controls width="100%">
                    <source src="${url}" type="video/${url.split('.').pop().toLowerCase()}">
                </video>`;
            }
            // 未知类型显示链接
            else {
                iframeText = `<a href="${url}" target="_blank">视频链接：${url}</a>`;
            }
        } catch (error) {
            iframeText = `<a href="${url}" target="_blank">视频链接：${url}</a>`;
        }

        // 插入编辑器
        restoreSelection();
        const range = window.getSelection().getRangeAt(0);
        const textNode = document.createTextNode(iframeText);
        
        range.deleteContents();
        range.insertNode(textNode);

        // 添加换行保证后续输入
        const br = document.createElement('br');
        editor.appendChild(br);

        syncContent();
        $('#videoModal').modal('hide');
        urlInput.value = '';
    } catch (error) {
        console.error('视频插入失败:', error);
        alert(`视频插入失败：${error.message}`);
    }
}

// 图片点击预览功能
function initImagePreview() {
  // 事件委托处理动态加载的图片
  editor.addEventListener('click', function(e) {
    const img = e.target.closest('.uploaded-image, .user-image');
    if (img) {
      e.preventDefault();
      
      // 获取高清原图地址
      const originalSrc = img.dataset.original || img.src;
      
      // 设置预览图片
      const previewImg = document.getElementById('previewImage');
      previewImg.src = originalSrc;
      
      // 显示模态框
      const modal = new bootstrap.Modal('#imagePreviewModal');
      modal.show();
    }
  });

  // 双击图片切换缩放模式
  let isZoomed = false;
  document.getElementById('previewImage').addEventListener('dblclick', function() {
    this.style.maxWidth = isZoomed ? '100%' : '150%';
    this.style.transform = isZoomed ? 'none' : 'translate(-50%, -50%)';
    isZoomed = !isZoomed;
  });
}

// 在DOMContentLoaded中调用初始化
document.addEventListener('DOMContentLoaded', function() {
  initImagePreview();
});
</script>
</body>
</html>
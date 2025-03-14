<?php
// 启用严格错误报告
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '1');

// 安全头设置
header("X-Frame-Options: DENY");
header("X-XSS-Protection: 1; mode=block");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; img-src 'self' data:; frame-src player.bilibili.com www.youtube.com www.youtube-nocookie.com; media-src 'self'");
header("Referrer-Policy: strict-origin-when-cross-origin");

// 引入必要的文件
require_once __DIR__ . '/include/functions.php';
// 安装检测函数
function checkInstallation() {
    $lockFile = __DIR__ . '/install.lock';
    $configFile = __DIR__ . '/include/config.php';

    // 第一步：检查安装锁文件
    if (!file_exists($lockFile)) {
        header("Location: install.php");
        exit();
    }

    // 第二步：检查配置文件是否存在
    if (!file_exists($configFile)) {
        header("Location: install.php");
        exit();
    }

    // 第三步：包含配置文件并验证常量
    require_once($configFile);
    $requiredConstants = ['DB_HOST', 'DB_USER', 'DB_PASS', 'DB_NAME'];
    foreach ($requiredConstants as $constant) {
        if (!defined($constant)) {
            header("Location: install.php");
            exit();
        }
    }

    // 第四步：验证数据库连接
    try {
        $testConn = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
        if ($testConn->connect_errno) {
            header("Location: install.php?error=db_connection");
            exit();
        }
        $testConn->close();
    } catch (Exception $e) {
        header("Location: install.php?error=db_connection");
        exit();
    }
}

// 执行安装检测
checkInstallation();

// 读取当前计数
require_once __DIR__ . '/include/function.php';
$views = incrementVisitCount();

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

function searchreplace(string $input): string {
    return str_replace(['"', "'", "%"], ['\"', "\'", "\\%"], $input);
}

// 数据库连接
try {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        header("Location: install.php?error=db_connection");
        exit();
    }
    $mysqli->set_charset('utf8mb4');
} catch (Exception $e) {
    header("Location: install.php?error=db_connection");
    exit();
}

// 初始化搜索参数
$searchParams = [
    'searchstr' => isset($_GET['searchstr']) ? sanitizeInput($_GET['searchstr']) : '',
    'search_nicheng' => isset($_GET['search_nicheng']) ? true : false,
    'typeid'    => isset($_GET['typeid']) ? intval($_GET['typeid']) : -1,
    'page'      => isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1
];

// 构建动态查询条件
$where = ["shenhe = 1"];
$bindParams = [];
$bindTypes = '';

// 处理分类过滤
if ($searchParams['typeid'] >= 0) {
    $where[] = "typeid = ?";
    $bindParams[] = $searchParams['typeid'];
    $bindTypes .= 'i';
}

// 处理搜索条件
if (!empty($searchParams['searchstr'])) {
    $searchValue = $mysqli->real_escape_string($searchParams['searchstr']);
    $searchValue = "%$searchValue%";
    
    if ($searchParams['search_nicheng']) {
        $where[] = "nicheng LIKE ?";
        $bindParams[] = $searchValue;
        $bindTypes .= 's';
    } else {
        $searchFields = ['thetitle', 'content', 'nicheng', 'reply', 'email', 'qq', 'ip'];
        
        if (!empty($searchFields)) {
            $conditions = [];
            foreach ($searchFields as $field) {
                $conditions[] = "$field LIKE ?";
                $bindParams[] = $searchValue;
                $bindTypes .= 's';
            }
            $where[] = '(' . implode(' OR ', $conditions) . ')';
        }
    }
}

// 获取所有分类
$categories = [];
$typeQuery = $mysqli->query("SELECT * FROM ".DB_PREFIX."typeid ORDER BY id");
if ($typeQuery !== false) {
    $categories = $typeQuery->fetch_all(MYSQLI_ASSOC);
    $typeQuery->close();
} else {
    error_log("[分类查询失败] ".date('Y-m-d H:i:s')." 错误信息: ".$mysqli->error);
    $categories = []; 
}

// 获取总记录数
$countQuery = "SELECT COUNT(*) FROM ".DB_PREFIX."book WHERE ".implode(' AND ', $where);
$stmt = $mysqli->prepare($countQuery);
if ($bindTypes) $stmt->bind_param($bindTypes, ...$bindParams);
$stmt->execute();
$totalMessages = $stmt->get_result()->fetch_row()[0];

// 分页处理
$pagesize = 10;
$pagecount = ceil($totalMessages / $pagesize);
$offset = ($searchParams['page'] - 1) * $pagesize;

// 构建分页参数
$paginationParams = [
    'searchstr' => $searchParams['searchstr'],
    'search_nicheng' => $searchParams['search_nicheng'] ? 1 : null,
    'typeid' => $searchParams['typeid'] >= 0 ? $searchParams['typeid'] : null
];

// 获取当前页数据
$query = "SELECT 
            id, 
            thetitle, 
            content, 
            nicheng,
            homepage,
            ipshiji,
            reply,
            time,
            replytime,
            qiaoqiao,
            qiaoqiaopass 
          FROM ".DB_PREFIX."book 
          WHERE ".implode(' AND ', $where)." 
          ORDER BY time DESC 
          LIMIT ?, ?";
$bindParamsLimit = array_merge($bindParams, [$offset, $pagesize]);
$bindTypesLimit = $bindTypes . 'ii';

$stmt = $mysqli->prepare($query);
if ($bindTypesLimit) $stmt->bind_param($bindTypesLimit, ...$bindParamsLimit);
$stmt->execute();
$messages = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="csrf-token" content="<?= generateCSRFToken() ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?= get_content('global.page_title') ?></title>
    <link rel="icon" href="./assets/image/favicon.ico" type="image/ico">
    <link href="./assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="./assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css">
    <link href="./assets/bootstrap-5.3.3/css/inc.css" rel="stylesheet">
</head>
<body>
    <div class="container">
        <header class="mb-4 text-center">
            <h1 class="display-5 fw-bold mb-3"><?= get_content('index.main_title') ?></h1>
            <h3 class="fw-bold mb-3"><?= get_content('index.welcome_text') ?></h3>
        </header>

        <div class="row mb-4">
            <div class="col-12">
                <div class="category-filter">
                    <h5 class="mb-3 d-flex align-items-center">
                        <i class="bi-tags me-2"></i> <?= get_content('index.quick_view') ?>
                    </h5>
                    <div class="d-flex flex-wrap gap-2">
                        <?php
                        $currentParams = $_GET;
                        unset($currentParams['typeid']);
                        $baseUrl = 'index.php?' . http_build_query($currentParams);
                        ?>
                        <a href="<?= $baseUrl ?>&typeid=-1" 
                           class="btn btn-outline-primary category-badge <?= $searchParams['typeid'] == -1 ? 'active' : '' ?>">
                           <i class="bi-grid"></i> <?= get_content('global.all_categories') ?>
                        </a>
                        
                        <?php if (is_array($categories) && !empty($categories)): ?>
                            <?php foreach ($categories as $cat): ?>
                                <a href="<?= $baseUrl ?>&typeid=<?= $cat['id'] ?>" 
                                   class="btn btn-outline-primary category-badge <?= $searchParams['typeid'] == $cat['id'] ? 'active' : '' ?>">
                                   <?= htmlspecialchars($cat['typename']) ?>
                                </a>
                            <?php endforeach; ?>
                        <?php else: ?>
                            <div class="alert alert-warning my-3">暂时没有可用的分类</div>
                        <?php endif; ?>
                    </div>
                </div>
            </div>
        </div>

		<div class="row mb-4">
		    <div class="col-12">
		        <a href="edit.php" class="btn btn-outline-primary category-badge">发表留言</a>
		    </div>
		</div>

        <div class="row mb-4">
            <div class="col-md-4">
                <div class="mb-3 d-flex align-items-center">
                    <div class="btn btn-outline-primary category-badge">
                        <h5 class="card-title"><?= get_content('index.total_msg') ?></h5>
                        <p class="card-text"><?= $totalMessages ?></p>
                    </div>
                </div>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <form class="search-form" method="get" action="index.php">
                    <input type="hidden" name="searchmode" value="1">
                    <div class="row">
                        <div class="col-md-3">
                            <input type="text" class="form-control" name="searchstr" 
                                   placeholder="<?= get_content('index.search_placeholder') ?>">
                        </div>
                        <div class="col-md-3">
                            <div class="form-check">
                                <input type="checkbox" class="form-check-input" id="searchNicheng" name="search_nicheng"
                                       <?= isset($searchParams['search_nicheng']) ? 'checked' : '' ?>>
                                <label class="form-check-label" for="searchNicheng">按昵称搜索</label>
                            </div>
                        </div>
                        <div class="col-md-3">
                            <select class="form-select" name="typeid">
                                <option value="-1" 
                                        <?= ($searchParams['typeid'] ?? -1) == -1 ? 'selected' : '' ?>>
                                    <?= get_content('global.all_categories') ?>
                                </option>
                                <?php 
                                $types = $mysqli->query("SELECT * FROM ".DB_PREFIX."typeid ORDER BY id");
                                while ($type = $types->fetch_assoc()): ?>
                                    <option value="<?= $type['id'] ?>" <?= $searchParams['typeid'] == $type['id'] ? 'selected' : '' ?>>
                                        <?= htmlspecialchars($type['typename']) ?>
                                    </option>
                                <?php endwhile; ?>
                            </select>
                        </div>
                        <div class="col-md-3">
                            <button type="submit" class="btn btn-primary w-100">
                                <?= get_content('global.search_btn') ?>
                            </button>
                        </div>
                    </div>
                </form>
            </div>
        </div>

        <div class="row mb-4">
            <div class="col-12">
                <div class="message-table">
                    <?php if (empty($messages)): ?>
                        <div class="no-results text-center">
                            <i class="bi <?= get_content('index.no_results.icon_class') ?>" style="font-size:4rem;"></i>
                            <h3 class="mt-4"><?= get_content('index.no_results.title') ?></h3>
                            <p class="text-muted mt-2"><?= get_content('index.no_results.subtitle') ?></p>
                        </div>
                    <?php else: ?>
                        <?php foreach ($messages as $message): ?>
                        <div class="message-card card shadow-sm mb-4">
                            <div class="card-header bg-light d-flex justify-content-between align-items-center">
                                <h5 class="mb-0 d-flex align-items-center">
                                    <i class="bi-chat-right-text me-2"></i>
                                    <?= htmlspecialchars($message['thetitle'] ?? get_content('messages.default_title')) ?>
                                </h5>
                                <span class="text-muted small">
                                    <?= get_content('messages.post_time') ?>
                                    <?= date('Y-m-d H:i', strtotime($message['time'] ?? 'now')) ?>
                                </span>
                            </div>
                            <div class="card-body">
                                <div class="row g-3">
                                    <div class="col-md-6">
                                        <div class="info-item d-flex align-items-center">
                                            <i class="bi-person-circle me-2"></i>
                                            <span class="fw-medium">
                                                <?= htmlspecialchars($message['nicheng'] ?? get_content('messages.user_info.anonymous')) ?>
                                            </span>
                                        </div>
                                    </div>
                                    <div class="col-md-6">
								<?php if(isset($message['homepage'])): ?>
									<div class="info-item d-flex align-items-center">
										<i class="bi-globe me-2"></i>
										<a href="<?= htmlspecialchars($message['homepage']) ?>" 
										   target="_blank" 
										   rel="noopener noreferrer"
										   class="text-truncate d-inline-block" 
										   style="max-width: 200px">
											<?= htmlspecialchars($message['homepage']) ?>
										</a>
									</div>
								<?php else: ?>
									<div class="info-item d-flex align-items-center">
										<i class="bi-globe me-2"></i>
										<span class="text-muted">
											<?= get_content('messages.user_info.homepage_missing') ?>
										</span>
									</div>
								<?php endif; ?>
                                        <div class="info-item d-flex align-items-center">
                                            <i class="bi-geo-fill me-2 text-primary"></i>
                                            <span class="text-muted small">
                                                <?= get_content('messages.user_info.info_shiji') ?>:
                                            </span>
                                            <span class="ip-location">
                                                <?= $message['ipshiji'] 
                                                    ? htmlspecialchars($message['ipshiji'])
                                                    : '<span class="text-muted">'.get_content('global.unknown_location').'</span>' ?>
                                            </span>
                                        </div>
                                    </div>
                                </div>
                                <div class="mt-4 border-top pt-3">
                                    <h6 class="fw-bold text-primary mb-3 d-flex align-items-center">
                                        <i class="bi-chat-quote me-2"></i>
                                        <?= get_content('messages.content_title') ?>
                                    </h6>
                                    <?php if (!empty($message['qiaoqiaopass'])): ?>
                                        <div class="encrypted-content" data-id="<?= $message['id'] ?>">
                                            <div class="alert alert-warning d-flex align-items-center">
                                                <i class="bi bi-lock me-2"></i>
                                                <span>内容被用户加密，请输入密码查看</span>
                                            </div>
                                            <div class="input-group mb-3">
                                                <input type="password" 
                                                       class="form-control password-input" 
                                                       placeholder="请输入访问密码"
                                                       data-id="<?= $message['id'] ?>">
                                                <button class="btn btn-outline-secondary verify-btn" 
                                                        type="button" 
                                                        data-id="<?= $message['id'] ?>">
                                                    <i class="bi bi-check"></i>
                                                </button>
                                            </div>
                                            <div class="invalid-feedback text-danger mb-2"></div>
                                        </div>
                                        <div class="original-content" 
                                             data-content="<?= htmlspecialchars($message['content']) ?>" 
                                             style="display:none;">
                                        </div>
                                    <?php else: ?>
                                        <div class="content-box bg-light p-3 rounded rich-text">
                                            <p><?= renderRichText($message['content']) ?></p>
                                        </div>
                                    <?php endif; ?>
                                </div>
                                <?php if (!empty($message['reply'])): ?>
                                    <div class="mt-4 border-top pt-3">
                                        <h6 class="fw-bold text-success mb-3 d-flex align-items-center">
                                            <i class="bi-chat-left-text me-2"></i>
                                            <?= get_content('messages.reply_title') ?>
                                            <small>
                                                <?= date('Y-m-d H:i', strtotime($message['reply_time'] ?? $message['time'] ?? 'now')) ?>
                                            </small>
                                        </h6>
                                        <div class="content-box bg-success bg-opacity-10 p-3 rounded rich-text">
                                            <p><?= renderRichText($message['reply']) ?></p>
                                        </div>
                                    </div>
                                <?php endif; ?>
                                <div class="mt-4 d-flex justify-content-end gap-2">
                                    <button class="btn btn-sm btn-outline-danger report-btn" 
                                            data-id="<?= $message['id'] ?? 0 ?>">
                                        <i class="bi-flag"></i>
                                        <?= get_content('messages.buttons.report') ?>
                                    </button>
                                    <button class="btn btn-sm btn-outline-secondary like-btn" 
                                            data-id="<?= $message['id'] ?>">
                                        <i class="bi-hand-thumbs-up"></i>
                                        <span class="count"><?= $message['likes'] ?? 0 ?></span>
                                        <?= get_content('messages.buttons.like') ?>
                                    </button>
                                </div>
                            </div>
                        </div>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </div>
            </div>
        </div>

        <?php if ($pagecount > 1): ?>
            <div class="row">
                <div class="col-12">
                    <nav class="mt-4">
                        <ul class="pagination justify-content-center">
                            <?php if ($searchParams['page'] > 1): ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= $paginationBase ?>1">
                                        <?= get_content('global.pagination.first') ?>
                                    </a>
                                </li>
                                <li class="page-item">
                                    <a class="page-link" href="<?= $paginationBase . ($searchParams['page'] - 1) ?>">
                                        <?= get_content('global.pagination.prev') ?>
                                    </a>
                                </li>
                            <?php endif; ?>

                            <?php for ($i = max(1, $searchParams['page'] - 2); $i <= min($pagecount, $searchParams['page'] + 2); $i++): ?>
                                <li class="page-item <?= $i == $searchParams['page'] ? 'active' : '' ?>">
                                    <a class="page-link" href="<?= $paginationBase . $i ?>">
                                        <?= $i ?>
                                    </a>
                                </li>
                            <?php endfor; ?>

                            <?php if ($searchParams['page'] < $pagecount): ?>
                                <li class="page-item">
                                    <a class="page-link" href="<?= $paginationBase . ($searchParams['page'] + 1) ?>">
                                        <?= get_content('global.pagination.next') ?>
                                    </a>
                                </li>
                                <li class="page-item">
                                    <a class="page-link" href="<?= $paginationBase . $pagecount ?>">
                                        <?= get_content('global.pagination.last') ?>
                                    </a>
                                </li>
                            <?php endif; ?>
                        </ul>
                    </nav>
                </div>
            </div>
        <?php endif; ?>

		<footer class="footer mt-5 py-4 border-top">
		    <div class="container text-center text-muted small">
		        <div class="row g-2">
		            <div class="col-12" style="font-size: 1rem;">
		                <?= sprintf(
		                    get_content('global.footer.tech_info'), 
		                    PHP_VERSION,
		                    $mysqli->server_version
		                ) ?>
		            </div>
		            <div class="col-12" style="font-size: 1rem;">
		                <?= str_replace(
		                    '{year}', 
		                    date('Y'), 
		                    get_content('global.footer.copyright')
		                ) ?>
		            </div>
		            <div class="col-12" style="font-size: 1rem;">
		                <?= get_content('global.footer.beian') ?>
		            </div>
		            <div class="view-counter" style="font-size: 1rem;">
		                <i class="bi-eye"></i>
		                本站已经访问次数：<?= number_format($views) ?>
		            </div>
		        </div>
		    </div>
		</footer>
	</div>
    <script src="../assets/bootstrap-5.3.3/js/bootstrap.bundle.min.js"></script>
<script>
    // 密码验证处理
    const PasswordHandler = {
        init: () => {
            document.querySelectorAll('.verify-btn').forEach(btn => {
                btn.dataset.originalHtml = btn.innerHTML;
                btn.addEventListener('click', PasswordHandler.handleVerify);
            });
        },

        handleVerify: async function() {
            const messageId = this.dataset.id;
            const container = this.closest('.encrypted-content');
            const input = container.querySelector('.password-input');
            const feedback = container.querySelector('.invalid-feedback');

            if (!input.value) {
                feedback.textContent = '密码不能为空';
                return;
            }

            Utils.setButtonState(this, true);
            
            try {
                const response = await Utils.fetchAPI('verify_password.php', 'POST', {
                    id: messageId,
                    password: input.value
                });

                const data = await response.json();
                
                if (data.success) {
                    PasswordHandler.showDecryptedContent(container, data.content);
                } else {
                    feedback.textContent = data.message || '密码验证失败';
                }
            } catch (error) {
                console.error('验证失败:', error);
                feedback.textContent = '服务器错误，请稍后再试';
            } finally {
                Utils.setButtonState(this, false);
            }
        },

        showDecryptedContent: (container, content) => {
            const originalContent = container.nextElementSibling;
            originalContent.querySelector('[data-content]').textContent = content;
            originalContent.style.display = 'block';
            container.style.display = 'none';
        }
    };

    // 通用功能模块
    const CommonFeatures = {
        initCopyButtons: () => {
            document.querySelectorAll('[data-copy-target]').forEach(btn => {
                btn.dataset.originalHtml = btn.innerHTML;
                btn.addEventListener('click', async function() {
                    try {
                        const target = document.querySelector(this.dataset.copyTarget);
                        await navigator.clipboard.writeText(target.textContent);
                        alert('内容已复制到剪贴板');
                    } catch (error) {
                        console.error('复制失败:', error);
                        alert('复制失败，请手动选择内容');
                    }
                });
            });
        },

        initReportButtons: () => {
            document.querySelectorAll('.report-btn').forEach(btn => {
                btn.dataset.originalHtml = btn.innerHTML;
                btn.dataset.loadingText = '提交举报...';
                
                btn.addEventListener('click', async function() {
                    if (!confirm('确定要举报此内容？')) return;
                    
                    Utils.setButtonState(this, true);
                    try {
                        const response = await Utils.fetchAPI('report.php', 'POST', {
                            id: this.dataset.id
                        });
                        
                        if (!response.ok) throw new Error(`HTTP ${response.status}`);
                        
                        const data = await response.json();
                        if (!data.success) throw new Error(data.error || '举报失败');
                        
                        alert('举报已受理！该内容将进入审核流程');
                    } catch (error) {
                        console.error('举报失败:', error);
                        alert(`操作失败: ${error.message}`);
                    } finally {
                        Utils.setButtonState(this, false);
                    }
                });
            });
        },

        initLikeButtons: () => {
            document.querySelectorAll('.like-btn').forEach(btn => {
                btn.dataset.originalHtml = btn.innerHTML;
                btn.dataset.loadingText = '点赞中...';
                
                btn.addEventListener('click', async function() {
                    Utils.setButtonState(this, true);
                    const countSpan = this.querySelector('.count');
                    
                    try {
                        const response = await Utils.fetchAPI('like.php', 'POST', {
                            id: this.dataset.id
                        });
                        
                        if (!response.ok) throw new Error(`HTTP ${response.status}`);
                        
                        const data = await response.json();
                        if (!data.success) throw new Error(data.error || '点赞失败');
                        
                        countSpan.textContent = data.likes;
                        this.classList.add('liked');
                        setTimeout(() => this.classList.remove('liked'), 1000);
                    } catch (error) {
                        console.error('点赞失败:', error);
                        alert(`操作失败: ${error.message}`);
                    } finally {
                        Utils.setButtonState(this, false);
                    }
                });
            });
        }
    };

    // 工具函数
    const Utils = {
        setButtonState: (button, isLoading) => {
            if (isLoading) {
                button.innerHTML = button.dataset.loadingText;
                button.disabled = true;
            } else {
                button.innerHTML = button.dataset.originalHtml;
                button.disabled = false;
            }
        },

        fetchAPI: (url, method = 'GET', data = null) => {
            const options = {
                method: method,
                headers: {
                    'X-CSRF-Token': document.querySelector('meta[name="csrf-token"]').content,
                    'Content-Type': 'application/json'
                }
            };

            if (data !== null) {
                options.body = JSON.stringify(data);
            }

            return fetch(url, options);
        }
    };

    // 处理视频加载错误
    function handleVideoError(iframe) {
        const container = iframe.closest('.video-container');
        if (!container) return;

        container.innerHTML = `
            <div class="alert alert-danger m-2">
                视频加载失败
                <button class="btn btn-sm btn-outline-danger float-end" 
                        onclick="this.closest('.video-container').remove()">
                    关闭
                </button>
            </div>
        `;
    }
    
</script>
</body>
</html>
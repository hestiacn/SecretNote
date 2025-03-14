<?php
// 数据库配置
define('DB_HOST', 'localhost');
define('DB_USER', 'www_bb');
define('DB_PASS', 'iy7qLJiBvmE*KB6.P');
define('DB_NAME', 'www_bb');
define('DB_PREFIX', 'gb_');
define('DB_CHARSET', 'utf8mb4');

// 对话树配置
define('COMMENT_TREE', true);
define('MAX_DEPTH', 3);
define('REPLY_PER_PAGE', 5);
define('TREE_ORDER', 'DESC');

// 管理员配置
define('ADMIN_USER', 'admin');
define('ADMIN_HASH', '$2y$10$jx1kxl/fIiVO2I8J8Xop/eorddFD5CuM/hKc6WJ4MJb41B8dqrW0m');

// 安全密钥
define('SITE_KEY', '".bin2hex(random_bytes(32))."');

// 调试模式
define('DEBUG_MODE', false);
-- Bluegem Guestbook Backup
-- Generated: 2025-03-10 19:08:25


-- Table structure for gb_admin_logs
DROP TABLE IF EXISTS `gb_admin_logs`;
CREATE TABLE `gb_admin_logs` (
  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `admin_id` int(10) unsigned NOT NULL,
  `action` varchar(50) NOT NULL,
  `target_table` varchar(30) DEFAULT NULL,
  `target_id` int(10) unsigned DEFAULT NULL,
  `details` text CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `ip_address` varbinary(16) NOT NULL,
  `user_agent` varchar(500) DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `idx_admin_action` (`admin_id`,`action`),
  CONSTRAINT `gb_admin_logs_ibfk_1` FOREIGN KEY (`admin_id`) REFERENCES `gb_admins` (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for gb_admin_logs
INSERT INTO `gb_admin_logs` VALUES ('1', '1', 'config_save', NULL, NULL, '配置类型: content, 备份文件: content_20250310185739.bak', '14', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:136.0) Gecko/20100101 Firefox/136.0', '2025-03-11 02:57:39');


-- Table structure for gb_admins
DROP TABLE IF EXISTS `gb_admins`;
CREATE TABLE `gb_admins` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `username` varchar(50) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `password` char(60) NOT NULL,
  `last_login` datetime DEFAULT NULL,
  `login_attempts` tinyint(3) unsigned DEFAULT 0,
  `locked_until` datetime DEFAULT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_username` (`username`),
  KEY `idx_login_status` (`login_attempts`,`locked_until`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for gb_admins
INSERT INTO `gb_admins` VALUES ('1', 'admin', '$2y$10$JICFRHSblvRGZDkQVW0zZupOdeDTfdSbm1952CrvUh40vbcrNdWea', '2025-03-11 00:48:13', '0', NULL, '2025-03-11 00:48:08');


-- Table structure for gb_book
DROP TABLE IF EXISTS `gb_book`;
CREATE TABLE `gb_book` (
  `typeid` int(10) unsigned DEFAULT 0 COMMENT '分类ID',
  `id` int(11) NOT NULL AUTO_INCREMENT COMMENT '唯一标识',
  `parentid` int(11) NOT NULL DEFAULT 0 COMMENT '父级留言ID',
  `depth` tinyint(3) unsigned DEFAULT 0 COMMENT '嵌套深度',
  `thetitle` varchar(255) NOT NULL COMMENT '留言标题',
  `nicheng` varchar(50) NOT NULL COMMENT '用户昵称',
  `homepage` varchar(255) DEFAULT NULL COMMENT '主页地址',
  `content` text NOT NULL COMMENT '留言内容',
  `allow_html` tinyint(1) DEFAULT 0 COMMENT '允许HTML标签',
  `editor_type` enum('markdown','rich-text') DEFAULT 'markdown' COMMENT '编辑器类型',
  `version` int(10) unsigned DEFAULT 1 COMMENT '内容版本号',
  `reply` text DEFAULT NULL COMMENT '管理员回复',
  `iszhiding` tinyint(1) unsigned DEFAULT 0 COMMENT '置顶优先级',
  `shenhe` tinyint(1) unsigned DEFAULT 1 COMMENT '审核状态',
  `is_comment` tinyint(1) unsigned DEFAULT 1 COMMENT '留言类型',
  `qiaoqiao` tinyint(1) unsigned DEFAULT 0 COMMENT '加密模式',
  `qiaoqiaopass` varchar(255) DEFAULT NULL COMMENT '访问密码',
  `ip` varbinary(16) NOT NULL COMMENT 'IP地址',
  `ipshiji` varchar(100) DEFAULT NULL COMMENT 'IP地理位置',
  `user_agent` varchar(255) DEFAULT NULL COMMENT '浏览器指纹',
  `time` datetime DEFAULT current_timestamp() COMMENT '创建时间',
  `replytime` datetime DEFAULT NULL COMMENT '回复时间',
  `browsetime` datetime DEFAULT NULL COMMENT '最后浏览时间',
  `media_type` enum('image','video','none') DEFAULT 'none' COMMENT '媒体类型',
  `local_image` varchar(255) DEFAULT NULL COMMENT '本地图片路径',
  `external_video` varchar(511) DEFAULT NULL COMMENT '外链视频地址',
  `video_thumbnail` varchar(255) DEFAULT NULL COMMENT '视频缩略图',
  `file_size` int(10) unsigned DEFAULT NULL COMMENT '文件大小(字节)',
  PRIMARY KEY (`id`),
  KEY `idx_media` (`media_type`),
  KEY `idx_thread` (`parentid`,`depth`),
  FULLTEXT KEY `idx_search` (`content`,`reply`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Data for gb_book
INSERT INTO `gb_book` VALUES ('0', '1', '0', '0', '系统演示', '蓝宝石留言本', NULL, '🎉 欢迎体验全新留言系统！\n\n主要更新与功能亮点：\n🌟 视频嵌入功能\n现在，您可以在留言中嵌入外部视频链接，让您的留言更加生动有趣。只需在\"外链视频地址\"字段中输入视频URL，视频缩略图将自动生成并展示。\n\n🔄 多级回复系统\n留言系统支持多级回复，您可以轻松地对其他用户的留言进行嵌套回复。回复的层级关系通过系统自动管理，让交流更加深入和有条理。\n\n🔒 安全性能增强\n我们对留言系统进行了全面的安全升级，包括增加访问密码保护（悄悄话功能），确保您的留言数据更加安全可靠。\n\n🌐 个人主页链接\n留言系统支持显示用户个人主页链接。只需输入以\"http\"开头的URL，即可在留言中展示可点击的个人主页链接。\n\n🤫 悄悄话功能\n现在，您可以向特定用户发送加密留言（悄悄话）。只需勾选加密模式，并设置访问密码，即可保护您的私密留言不被他人查看。注意：默认密码仅为示例，请务必设置自己的密码。\n\n✅ 新增举报功能\n如果您认为某个留言内容不利于展示可使用右下角的举报功能，内容将被移除展示。\n\n🎨 多媒体支持\n留言系统支持上传本地图片和嵌入外部视频。您可以在留言中展示丰富的多媒体内容，让您的留言更加吸引人。提示：查看右侧图片展示区域，体验多媒体留言的魅力。\n\n📝 示例留言操作指南\n    回复留言：尝试回复本条消息，体验多级回复系统的便捷性。\n    查看审核状态：留意留言列表中的审核状态标记，了解留言是否已通过审核。\n    上传图片/视频：在留言时，您可以选择上传本地图片或嵌入外部视频，丰富留言内容。\n    设置悄悄话：如需隐私发表匿名留言，请勾选加密模式并设置访问密码。\n\n🌟 重点提示\n您发布的留言不需要审核，发布成功后将即时发布到首页，您可以刷新页面查看。因为我们启用了违禁词和无意义留言过滤功能，所以请放心留言。\n\n📢 温馨提醒\n如遇任何问题或建议，请随时匿名留言到建议。\n\n希望您在全新留言系统中留下美好的回忆！', '0', 'markdown', '1', NULL, '0', '1', '1', '0', NULL, '\0\0', '上海', NULL, '2025-03-11 00:48:08', NULL, NULL, 'none', 'touxiang/default3/1.gif', NULL, NULL, NULL);


-- Table structure for gb_like
DROP TABLE IF EXISTS `gb_like`;
CREATE TABLE `gb_like` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` int(11) NOT NULL,
  `ip` varchar(45) NOT NULL,
  `user_agent` varchar(255) DEFAULT NULL,
  `session_id` varchar(128) DEFAULT NULL,
  `created_at` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_unique_vote` (`message_id`,`ip`),
  CONSTRAINT `gb_like_ibfk_1` FOREIGN KEY (`message_id`) REFERENCES `gb_book` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Table structure for gb_message_views
DROP TABLE IF EXISTS `gb_message_views`;
CREATE TABLE `gb_message_views` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `message_id` int(11) NOT NULL,
  `user_id` int(11) DEFAULT NULL,
  `ip_address` varbinary(16) NOT NULL,
  `view_time` datetime DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  KEY `message_id` (`message_id`),
  CONSTRAINT `gb_message_views_ibfk_1` FOREIGN KEY (`message_id`) REFERENCES `gb_book` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Table structure for gb_reports
DROP TABLE IF EXISTS `gb_reports`;
CREATE TABLE `gb_reports` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `report_time` datetime DEFAULT current_timestamp(),
  `reporter_id` int(11) DEFAULT NULL,
  `reported_id` int(11) NOT NULL,
  `reason` text NOT NULL,
  `status` enum('pending','processed','ignored') DEFAULT 'pending',
  `admin_id` int(11) DEFAULT NULL,
  `action_taken` text DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `reported_id` (`reported_id`),
  CONSTRAINT `gb_reports_ibfk_1` FOREIGN KEY (`reported_id`) REFERENCES `gb_book` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


-- Table structure for gb_typeid
DROP TABLE IF EXISTS `gb_typeid`;
CREATE TABLE `gb_typeid` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `typename` varchar(200) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
  `addtime` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_typename` (`typename`(100))
) ENGINE=InnoDB AUTO_INCREMENT=5 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- Data for gb_typeid
INSERT INTO `gb_typeid` VALUES ('1', '悄悄话专区', '2025-03-11 00:48:08');
INSERT INTO `gb_typeid` VALUES ('2', '用户反馈', '2025-03-11 00:48:08');
INSERT INTO `gb_typeid` VALUES ('3', '技术交流', '2025-03-11 00:48:08');
INSERT INTO `gb_typeid` VALUES ('4', '产品建议', '2025-03-11 00:48:08');


-- Table structure for gb_verified_access
DROP TABLE IF EXISTS `gb_verified_access`;
CREATE TABLE `gb_verified_access` (
  `id` int(10) unsigned NOT NULL AUTO_INCREMENT,
  `message_id` int(11) NOT NULL,
  `session_id` char(40) NOT NULL,
  `access_token` char(64) NOT NULL,
  `expires_at` datetime NOT NULL,
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uniq_token` (`access_token`),
  KEY `message_id` (`message_id`),
  CONSTRAINT `gb_verified_access_ibfk_1` FOREIGN KEY (`message_id`) REFERENCES `gb_book` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;


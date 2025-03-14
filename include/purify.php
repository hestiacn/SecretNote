<?php
require_once __DIR__ . '/assets/htmlpurifier/library/HTMLPurifier.auto.php';

use HTMLPurifier;
use HTMLPurifier_Config;

/**
 * HTML内容净化器
 * @param string $dirtyHtml 待净化的HTML
 * @return string 净化后的安全HTML
 */
function cleanHtml(string $dirtyHtml): string {
    // 配置白名单
    $config = HTMLPurifier_Config::createDefault();
    
    // 允许的HTML标签和属性
    $config->set('HTML.Allowed', 'p,strong,em,u,h1,h2,h3,h4,h5,h6,img[src|alt],a[href],div,span,br,hr,ul,ol,li,blockquote,pre,code,iframe[src|frameborder|scrolling|class|allowfullscreen|width|height],video,source');
    
    // 允许iframe的域名白名单
    $config->set('URI.SafeIframeRegexp', '%^(https?:)?//(player\.bilibili\.com|www\.youtube\.com/embed/)%');
    
    // 允许全屏功能
    $config->set('HTML.IframeAllowFullscreen', true);
    
    // 其他配置
    $config->set('Attr.AllowedClasses', [
        'bilibili-iframe', 'youtube-iframe', 
        'image-wrapper', 'video-container'
    ]);
    
    // 缓存目录
    $config->set('Cache.SerializerPath', __DIR__.'/../cache/htmlpurifier');

    $purifier = new HTMLPurifier($config);
    return $purifier->purify($dirtyHtml);
}

/**
 * 纯文本过滤
 * @param string $input 用户输入
 * @return string 安全文本
 */
function sanitizeText(string $input): string {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}
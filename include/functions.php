<?php
declare(strict_types=1);
require_once __DIR__ . '/../assets/htmlpurifier/library/HTMLPurifier.auto.php';
// HTMLPurifier配置

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
/**
 * 安全渲染富文本内容
 */
function renderRichText(string $rawContent): string {
    try {
        $content = purifyAndRenderContent($rawContent);
        // 强制添加延迟加载属性
        return preg_replace('/<img\s+([^>]*)>/i', '<img $1 loading="lazy">', $content);
    } catch (RuntimeException $e) {
        error_log("内容渲染失败: " . $e->getMessage());
        return '<div class="alert alert-danger">内容解析错误</div>';
    }
}

/**
 * 完整净化处理流程
 */
function purifyAndRenderContent(string $content): string {
    // 预处理阶段
    $processed = preprocessContent($content);
    
    // 安全净化阶段
    $cleanContent = purifyHTML($processed);
    
    // 后处理阶段
    return postprocessContent($cleanContent);
}

/**
 * 预处理：解码实体+转换媒体
 */
function preprocessContent(string $content): string {
    // 修正常量拼写
    $decoded = html_entity_decode($content, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    // 处理换行符
    $withNewlines = preg_replace('/(\r\n|\r|\n)+/', "\n", $decoded);
    $withBreaks = nl2br($withNewlines, false);

    // 修正Markdown图片正则表达式
    $withImages = preg_replace_callback(
        '/!$$([^$$]*)\]$([^)]+)$/',
        function ($matches) {
            $alt = htmlspecialchars($matches[1], ENT_QUOTES);
            $src = htmlspecialchars($matches[2], ENT_QUOTES);
            return "<img src='$src' alt='$alt' class='user-image'>";
        },
        $withBreaks
    );

    // 转换视频链接
    return preg_replace_callback(
        '/https?:\/\/(?:www\.)?(?:youtube\.com\/watch\?v=|youtu\.be\/|bilibili\.com\/(?:video\/|player.html\?bvid=|player.html\?aid=))([\w-]+)/',
        function ($matches) {
            return generateVideoEmbed($matches);
        },
        $withImages
    );
}

/**
 * 生成视频嵌入代码
 */
function generateVideoEmbed(array $matches): string {
    $url = $matches[0];
    $videoId = $matches[1];

    // B站视频
    if (strpos($url, 'bilibili') !== false) {
        return sprintf(
            '<iframe class="bilibili-iframe" 
                src="//player.bilibili.com/player.html?bvid=%s" 
                frameborder="0" 
                scrolling="no"
                allowfullscreen></iframe>',
            $videoId
        );
    }
    
    // YouTube视频
    if (strpos($url, 'youtube') !== false || strpos($url, 'youtu.be') !== false) {
        return sprintf(
            '<iframe class="youtube-iframe" 
                src="//www.youtube.com/embed/%s?rel=0&modestbranding=1" 
                frameborder="0" 
                allowfullscreen></iframe>',
            $videoId
        );
    }
    
    // 腾讯视频
    if (strpos($url, 'v.qq.com') !== false) {
        return sprintf(
            '<iframe class="tencent-iframe" 
                src="//v.qq.com/txp/vidembed/%s?auto=0" 
                frameborder="0" 
                allowfullscreen></iframe>',
            $videoId
        );
    }
    
    // 优酷视频
    if (strpos($url, 'youku.com') !== false) {
        return sprintf(
            '<iframe class="youku-iframe" 
                src="//player.youku.com/embed/%s" 
                frameborder="0" 
                allowfullscreen></iframe>',
            $videoId
        );
    }
    
    // Vimeo视频
    if (strpos($url, 'vimeo.com') !== false) {
        return sprintf(
            '<iframe class="vimeo-iframe" 
                src="//player.vimeo.com/video/%s" 
                frameborder="0" 
                allowfullscreen></iframe>',
            $videoId
        );
    }

    // 默认返回原始链接（如果无法识别）
    return sprintf(
        '<a href="%s" target="_blank" class="external-video-link">外部视频链接</a>',
        htmlspecialchars($url, ENT_QUOTES)
    );
}

/**
 * HTML安全净化
 */
function purifyHTML(string $content): string {
    $config = HTMLPurifier_Config::createDefault();
    
    // 安全配置
    $config->set('HTML.DefinitionID', 'secure-render-v3');
    $config->set('HTML.Allowed', '
        p,br,div,span,
        a[href|title|target=_blank],
        img[src|alt|class|loading],
        pre,code,
        iframe[src|frameborder|scrolling|class|allowfullscreen|sandbox],
        video[controls|width|height|poster],
        source[src|type],
        h1,h2,h3,h4,h5,h6,
        ul,ol,li,
        strong,em,blockquote,
        figure,figcaption
    ');
    $config->set('HTML.SafeIframe', true);
    $config->set('URI.SafeIframeRegexp', '%^(https?:)?//(www\.youtube(?:-nocookie)?\.com/embed/|player\.bilibili\.com/)%');
    $config->set('Attr.AllowedClasses', [
        'bilibili-iframe', 'youtube-iframe', 
        'image-wrapper', 'video-container', 
        'user-image', 'alert', 'alert-danger',
        'language-*', 'code-block' 
    ]);
    $config->set('HTML.TargetBlank', true);

    // 扩展定义
    if ($def = $config->maybeGetRawHTMLDefinition()) {
        $def->addElement('video', 'Block', 'Flow', 'Common', [
            'src' => 'URI',
            'controls' => 'Bool',
            'width' => 'Length',
            'height' => 'Length',
            'poster' => 'URI'
        ]);
        $def->addElement('source', 'Block', 'Empty', 'Common', [
            'src' => 'URI',
            'type' => 'Text'
        ]);
        $def->addAttribute('iframe', 'sandbox', 'Text');
        $def->addAttribute('img', 'loading', 'Enum#lazy,eager');
        $def->addAttribute('pre', 'class', 'Text');
        $def->addAttribute('code', 'class', 'Text');
    }

    $purifier = new HTMLPurifier($config);
    return $purifier->purify($content);
}

/**
 * 后处理：增强显示效果
 */
function postprocessContent(string $content): string {
    // 合并后的处理逻辑
    $cleanContent = preg_replace('/(<br[^>]*>[\n\t ]*){3,}/i', '<br class="multi-break">', $content);

    $withVideoContainers = preg_replace(
        '/<iframe([^>]+)><\/iframe>/i',
        '<div class="video-container"><iframe$1></iframe></div>',
        $cleanContent
    );

    return processImages($withVideoContainers);
}

/**
 * 图片增强处理
 */
function processImages(string $content): string {
    return preg_replace_callback('/<img\s+([^>]*)>/i', function($matches) {
        $attrs = parseAttributes($matches[1]);

        // 添加默认属性
        $attrs['loading'] = $attrs['loading'] ?? 'lazy';
        $attrs['alt'] = $attrs['alt'] ?? '用户上传图片';

        // 自动生成高清图地址（核心修改部分）▼
        if (!isset($attrs['data-original'])) {
            $src = $attrs['src'] ?? '';
            
            /**
             * 匹配包含 /thumbs/thumb_ 的路径结构
             * 示例路径：/uploads/thumbs/thumb_abc123.jpg
             * 匹配分组：
             * - $1: /thumbs/thumb_ 
             * - $2: abc123 (文件名哈希)
             * - $3: jpg (扩展名)
             */
            if (preg_match('#(/thumbs/thumb_)([a-f0-9]+)\.(jpg|png|webp)$#i', $src, $matches)) {
                // 生成高清图路径：/uploads/abc123.jpg
                $attrs['data-original'] = str_replace(
                    $matches[1],  // 替换目标：/thumbs/thumb_
                    '/',          // 替换为：/
                    $src          // 原路径
                );
                
                // 调试日志（生产环境可注释掉）
                error_log("[Image Processing] Thumbnail path converted: {$src} => {$attrs['data-original']}");
            }
        }
        // ▲ 核心修改结束

        // 构建属性字符串（过滤无效属性后）
        $allowedAttrs = ['src', 'alt', 'loading', 'class', 'data-original'];
        $filteredAttrs = array_intersect_key($attrs, array_flip($allowedAttrs));
        
        $attrString = implode(' ', array_map(
            fn($k, $v) => sprintf('%s="%s"', $k, htmlspecialchars($v, ENT_QUOTES)),
            array_keys($filteredAttrs),
            $filteredAttrs
        ));

        // 提取标题生成说明（保留原始title属性）
        $caption = '';
        if (!empty($attrs['title'])) {
            $caption = '<figcaption class="image-caption">'
                      . htmlspecialchars($attrs['title'], ENT_QUOTES)
                      . '</figcaption>';
            unset($attrs['title']); // 移除临时属性
        }

        return '<figure class="image-wrapper" style="position:relative">'
               . "<img {$attrString} style='cursor: zoom-in'>"
               . $caption
               . '</figure>';
    }, $content);
}

/**
 * 解析HTML属性为关联数组
 */
function parseAttributes(string $attrStr): array {
    $attrs = [];
    preg_match_all('/(\w+)=["\']?([^"\'\s]*)["\']?/', $attrStr, $matches, PREG_SET_ORDER);
    
    foreach ($matches as $m) {
        $attrs[strtolower($m[1])] = htmlspecialchars_decode($m[2]);
    }
    return $attrs;
}

/**
 * 获取本地化文本内容
 */
function get_content(string $key): string {
    static $content = null;
    
    if ($content === null) {
        $configFile = __DIR__ . '/content.json';
        
        if (!file_exists($configFile)) {
            throw new RuntimeException("语言文件缺失: $configFile");
        }
        
        $json = file_get_contents($configFile);
        $content = json_decode($json, true, 512, JSON_THROW_ON_ERROR);
    }
    
    $path = explode('.', $key);
    $current = $content;
    
    foreach ($path as $p) {
        if (!isset($current[$p])) {
            return "[$key]";
        }
        $current = $current[$p];
    }
    
    return is_string($current) ? $current : (string)$current;
}

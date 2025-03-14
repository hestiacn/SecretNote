<?php
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');

header('Content-Type: application/json');

// 会话安全设置
session_start([
    'cookie_httponly' => true,
    'cookie_samesite' => 'Strict'
]);

// 验证CSRF令牌
if (!isset($_POST['csrf_token']) || $_SESSION['csrf_token'] !== $_POST['csrf_token']) {
    http_response_code(403);
    die(json_encode(['errno' => 403, 'message' => 'CSRF token验证失败']));
}

try {
    // 验证文件上传
    if (empty($_FILES['image']) || $_FILES['image']['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException('文件上传失败，错误码：'.($_FILES['image']['error'] ?? '未知错误'));
    }

    $file = $_FILES['image'];
    $uploadDir = __DIR__.'/../uploads/';
    $thumbDir = $uploadDir.'thumbs/';
    $allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    $maxSize = 5 * 1024 * 1024; // 5MB

    // 创建目录
    foreach ([$uploadDir, $thumbDir] as $dir) {
        if (!file_exists($dir) && !mkdir($dir, 0755, true)) {
            throw new RuntimeException('无法创建上传目录');
        }
    }

    // 验证文件类型
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    if (!in_array($mimeType, $allowedTypes, true)) {
        throw new InvalidArgumentException('不支持的文件类型：'.$mimeType);
    }

    // 验证文件大小
    if ($file['size'] > $maxSize) {
        throw new LengthException('文件大小超过5MB限制');
    }

    // 生成安全文件名
    $extension = 'webp'; // 强制转换为 WebP 格式
    $uniqueName = hash('sha256', uniqid().$file['name']).'.'.$extension;
    $targetPath = $uploadDir.$uniqueName;

    // 处理图片转换为 WebP
    $source = $file['tmp_name'];
    $image = match ($mimeType) {
        'image/jpeg' => imagecreatefromjpeg($source),
        'image/png' => imagecreatefrompng($source),
        'image/gif' => imagecreatefromgif($source),
        'image/webp' => imagecreatefromwebp($source),
        default => throw new InvalidArgumentException('不支持的图片格式')
    };

    // 保存为 WebP 格式
    if (!imagewebp($image, $targetPath, 85)) {
        throw new RuntimeException('WebP 格式转换失败');
    }
    imagedestroy($image);

    // 返回结果
    echo json_encode([
        'errno' => 0,
        'data' => [
            'url' => '/uploads/'.$uniqueName,
            'dimensions' => [
                'original' => [imagesx($image), imagesy($image)]
            ]
        ]
    ]);

} catch (Exception $e) {
    http_response_code(500);
    error_log('图片上传错误：'.$e->getMessage());
    echo json_encode([
        'errno' => 500,
        'message' => '服务器处理错误：'.$e->getMessage()
    ]);
}
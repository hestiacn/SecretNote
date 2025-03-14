<?php
declare(strict_types=1);
error_reporting(E_ALL);
ini_set('display_errors', '0');

header('Content-Type: application/json');

session_start();

// 验证CSRF令牌
if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== ($_SESSION['csrf_token'] ?? '')) {
    http_response_code(403);
    die(json_encode(['errno' => 403, 'message' => 'CSRF token验证失败']));
}

// 验证文件上传
if (empty($_FILES['image'])) {
    http_response_code(400);
    die(json_encode(['errno' => 400, 'message' => '未收到文件']));
}

$file = $_FILES['image'];
$uploadDir = __DIR__.'/../uploads/';
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
$maxSize = 2 * 1024 * 1024;

try {
    // 验证文件类型
    if (!in_array($file['type'], $allowedTypes)) {
        throw new Exception('不支持的文件类型');
    }

    // 验证文件大小
    if ($file['size'] > $maxSize) {
        throw new Exception('文件大小超过限制');
    }

    // 生成安全文件名
    $extension = pathinfo($file['name'], PATHINFO_EXTENSION);
    $safeFilename = md5(uniqid().$file['name']).'.'.$extension;
    $targetPath = $uploadDir.$safeFilename;

    // 移动文件
    if (!move_uploaded_file($file['tmp_name'], $targetPath)) {
        throw new Exception('文件保存失败');
    }

    // 返回成功响应
    echo json_encode([
        'errno' => 0,
        'message' => '上传成功',
        'data' => [
            'url' => '/uploads/'.$safeFilename,
            'alt' => pathinfo($file['name'], PATHINFO_FILENAME),
            'width' => 0,  // 可添加图像处理逻辑获取尺寸
            'height' => 0
        ]
    ]);
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['errno' => 500, 'message' => $e->getMessage()]);
}
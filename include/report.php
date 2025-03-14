<?php
session_start();
require_once 'include/config.php'; // 确保已加载数据库配置

$messageId = isset($_GET['id']) ? (int)$_GET['id'] : null;
if (!$messageId) {
    die('无效的留言ID');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $reason = sanitizeInput($_POST['reason']);
    if (empty($reason)) {
        $error = '举报原因不能为空';
    } else {
        $stmt = $mysqli->prepare("INSERT INTO {$_SESSION['db']['prefix']}reports (reporter_id, reported_id, reason) VALUES (?, ?, ?)");
        $stmt->bind_param('iis', $_SESSION['user_id'] ?? null, $messageId, $reason); // 假设有用户系统，否则使用null
        $stmt->execute();
        header('Location: index.php'); // 重定向到留言列表或主页
        exit;
    }
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>举报留言</title>
    <link href="assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="assets/bootstrap-icons-1.11.3/font/bootstrap-icons.min.css">
</head>
<body>
    <div class="container mt-5">
        <h2 class="mb-4">举报留言</h2>
        <?php if (isset($error)): ?>
            <div class="alert alert-danger" role="alert">
                <?= $error ?>
            </div>
        <?php endif; ?>
        <form method="post">
            <div class="mb-3">
                <label for="reason" class="form-label">举报原因</label>
                <textarea class="form-control" id="reason" name="reason" rows="3" required></textarea>
            </div>
            <button type="submit" class="btn btn-danger">提交举报</button>
        </form>
    </div>
</body>
</html>
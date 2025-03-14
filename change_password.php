<?php
session_start();
require_once('include/config.php');
require_once('include/functions.php');

// 验证用户登录
if (!isset($_SESSION['user_id']) || !$_SESSION['user_id']) {
    header('Location: login.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 验证CSRF令牌
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        die('CSRF令牌验证失败');
    }

    $old_password = $_POST['old_password'];
    $new_password = $_POST['new_password'];
    $confirm_new_password = $_POST['confirm_new_password'];

    // 验证密码
    if (empty($old_password) || empty($new_password)) {
        die('旧密码和新密码不能为空');
    }
    if ($new_password !== $confirm_new_password) {
        die('两次输入的新密码不一致');
    }

    // 数据库连接
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        die("数据库连接失败: " . $mysqli->connect_error);
    }

    // 获取当前用户信息
    $stmt = $mysqli->prepare("SELECT password FROM {$_SESSION['db']['prefix']}users WHERE id = ?");
    $stmt->bind_param('i', $_SESSION['user_id']);
    $stmt->execute();
    $stmt->bind_result($hashed_password);
    $stmt->fetch();

    // 验证旧密码
    if (!password_verify($old_password, $hashed_password)) {
        die('旧密码不正确');
    }

    // 更新新密码
    $new_hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
    $stmt = $mysqli->prepare("UPDATE {$_SESSION['db']['prefix']}users SET password = ? WHERE id = ?");
    $stmt->bind_param('si', $new_hashed_password, $_SESSION['user_id']);
    if ($stmt->execute()) {
        echo '密码修改成功！';
    } else {
        die('密码修改失败: ' . $stmt->error);
    }

    $stmt->close();
    $mysqli->close();
}

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>修改密码</title>
    <link href="assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">修改密码</h3>
                    </div>
                    <div class="card-body">
                        <form action="change_password.php" method="post">
                            <div class="mb-3">
                                <label for="old_password" class="form-label">旧密码</label>
                                <input type="password" class="form-control" id="old_password" name="old_password" required>
                            </div>
                            <div class="mb-3">
                                <label for="new_password" class="form-label">新密码</label>
                                <input type="password" class="form-control" id="new_password" name="new_password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_new_password" class="form-label">确认新密码</label>
                                <input type="password" class="form-control" id="confirm_new_password" name="confirm_new_password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">修改密码</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>
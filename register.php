<?php
session_start();
require_once('include/config.php');
require_once('include/functions.php');

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 验证CSRF令牌
    if (!validateCSRFToken($_POST['csrf_token'] ?? '')) {
        die('CSRF令牌验证失败');
    }

    $username = sanitizeInput($_POST['username']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    // 验证用户名和密码
    if (empty($username) || empty($password)) {
        die('用户名和密码不能为空');
    }
    if ($password !== $confirm_password) {
        die('两次输入的密码不一致');
    }

    // 密码哈希
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // 数据库连接
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    if ($mysqli->connect_errno) {
        die("数据库连接失败: " . $mysqli->connect_error);
    }

    // 检查用户名是否已存在
    $stmt = $mysqli->prepare("SELECT id FROM {$_SESSION['db']['prefix']}users WHERE username = ?");
    $stmt->bind_param('s', $username);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        die('用户名已存在');
    }

    // 插入新用户
    $stmt = $mysqli->prepare("INSERT INTO {$_SESSION['db']['prefix']}users (username, password) VALUES (?, ?)");
    $stmt->bind_param('ss', $username, $hashed_password);
    if ($stmt->execute()) {
        echo '注册成功！您可以登录了。';
    } else {
        die('注册失败: ' . $stmt->error);
    }

    $stmt->close();
    $mysqli->close();
}
?>

<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>用户注册</title>
    <link href="assets/bootstrap-5.3.3/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
    <div class="container mt-5">
        <div class="row justify-content-center">
            <div class="col-md-6">
                <div class="card">
                    <div class="card-header">
                        <h3 class="text-center">用户注册</h3>
                    </div>
                    <div class="card-body">
                        <form action="register.php" method="post">
                            <div class="mb-3">
                                <label for="username" class="form-label">用户名</label>
                                <input type="text" class="form-control" id="username" name="username" required>
                            </div>
                            <div class="mb-3">
                                <label for="password" class="form-label">密码</label>
                                <input type="password" class="form-control" id="password" name="password" required>
                            </div>
                            <div class="mb-3">
                                <label for="confirm_password" class="form-label">确认密码</label>
                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                            </div>
                            <button type="submit" class="btn btn-primary w-100">注册</button>
                        </form>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>


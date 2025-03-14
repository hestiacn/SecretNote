<?php
session_start();
require __DIR__ . '/config1.php';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $mysqli = new mysqli(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    $message_id = (int)$_POST['id'];
    $password = $_POST['password'];
    
    $stmt = $mysqli->prepare("SELECT qiaoqiaopass FROM pre_book WHERE id = ?");
    $stmt->bind_param('i', $message_id);
    $stmt->execute();
    
    $result = $stmt->get_result();
    if ($result->num_rows === 1) {
        $row = $result->fetch_assoc();
        if (password_verify($password, $row['qiaoqiaopass'])) {
            $_SESSION['verified_messages'][$message_id] = true;
            header("Location: index.php");
            exit;
        }
    }
    die("密码验证失败");
}
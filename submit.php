<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $userCaptcha = $_POST['captcha'];
    $captcha = $_SESSION['captcha'];

    if ($userCaptcha === $captcha) {
        echo "验证码正确！";
    } else {
        echo "验证码错误！";
    }
}
?>
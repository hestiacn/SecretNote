<?php
session_start();

// 字体路径（确保大小写正确）
$font = __DIR__ . '/../assets/fonts/Arial.ttf';
if (!file_exists($font)) {
    die("字体文件未找到: " . realpath($font)); // 显示实际路径
}

// 生成验证码
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
$code = substr(str_shuffle($chars), 0, 4);
$_SESSION['captcha'] = $code;

// 创建图像
$width = 120;
$height = 40;
$image = imagecreatetruecolor($width, $height);
if (!$image) die("无法创建图像资源");

// 设置颜色
$bgColor = imagecolorallocate($image, 255, 255, 255);
$textColor = imagecolorallocate($image, 0, 0, 0);
imagefilledrectangle($image, 0, 0, $width, $height, $bgColor);

// 添加干扰线
for ($i = 0; $i < 5; $i++) {
    $lineColor = imagecolorallocate($image, rand(0,255), rand(0,255), rand(0,255));
    imageline($image, rand(0,$width), rand(0,$height), rand(0,$width), rand(0,$height), $lineColor);
}

// 写入文字（居中）
$fontSize = 20;
$angle = rand(-10, 10);
$textbox = imagettfbbox($fontSize, $angle, $font, $code);
$textWidth = $textbox[2] - $textbox[0];
$textHeight = $textbox[3] - $textbox[5];
$x = ($width - $textWidth) / 2;
$y = ($height - $textHeight) / 2 + $fontSize;

// 确保输出前无任何内容
ob_clean(); // 清除输出缓冲区
header('Content-type: image/png');
imagettftext($image, $fontSize, $angle, $x, $y, $textColor, $font, $code);
imagepng($image);
imagedestroy($image);
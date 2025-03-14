<?php
// include/ip.php

function getIPLocation(string $ip): string {
    $cacheDir = __DIR__.'/../cache';
    $cacheFile = $cacheDir.'/'.md5($ip).'.json';
    $expire = 604800; 

    // 创建缓存目录
    if (!file_exists($cacheDir)) {
        mkdir($cacheDir, 0755, true);
    }

    try {
        // 尝试读取缓存
        if (file_exists($cacheFile) && (time() - filemtime($cacheFile)) < $expire) {
            $data = json_decode(file_get_contents($cacheFile), true);
            if ($data['code'] == 200) return formatLocation($data);
        }

        // 主API请求
        $apiResponse = file_get_contents("https://cn.apihz.cn/api/ip/chaapi.php?id=10002193&key=7e1f5d0b23db5803520f39f63c917368&ip=".$ip);
        $data = json_decode($apiResponse, true);

        // 保存缓存
        if ($data['code'] == 200) {
            file_put_contents($cacheFile, $apiResponse);
            return formatLocation($data);
        }

        return '未知地区';
    } catch (Exception $e) {
        error_log("IP定位失败: ".$e->getMessage()." IP:{$ip}");
        return '服务不可用';
    }
}

function formatLocation(array $data): string {
    // 仅提取需要的字段
    $location = [
        'guo' => $data['guo'] ?? '',
        'sheng' => $data['sheng'] ?? '',
	   'shi' => $data['shi'] ?? $data['sheng'] ?? ''
    ];
    
    // 过滤空值并去除重复
    $filtered = array_filter($location, function($v) { 
        return $v !== '' && $v !== null;
    });
    
    // 特殊处理省市同名情况（如重庆）
    if (count($filtered) > 1 && $filtered['sheng'] === $filtered['shi']) {
        unset($filtered['shi']);
    }
    return implode('-', $filtered) ?: '未知地区';
}
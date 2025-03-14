<?php

// 添加在文件最开头
spl_autoload_register(function ($class) {
    $file = __DIR__ . '/' . $class . '.php';
    if (file_exists($file)) {
        require $file;
    }
});

require_once __DIR__ . '/Ip.php';

class IpTester {
    private $testCases = [
        'IPv4' => [
            '114.114.114.114' => '江苏南京',
            '202.96.134.33'   => '上海',
            '123.125.81.6'    => '北京',
            '8.8.8.8'         => '美国'
        ],
        'IPv6' => [
            '2001:da8::20f'    => '教育网',
            '2400:3200::1'     => '浙江杭州',
            '2001:4860:4860::8888' => 'Google DNS'
        ]
    ];

    public function runTest($customIp = null) {
        try {
            if ($customIp) {
                return $this->testSingleIp($customIp);
            }
            
            $results = [];
            foreach ($this->testCases as $type => $cases) {
                foreach ($cases as $ip => $expected) {
                    $results[] = $this->testSingleIp($ip, $expected);
                }
            }
            return $results;
        } catch (Exception $e) {
            return ['error' => $e->getMessage()];
        }
    }

    private function testSingleIp($ip, $expected = null) {
        $result = Ip::find($ip);
        
        return [
            'ip'       => $ip,
            'raw_data' => $result,
            'location' => isset($result[1]) ? "{$result[1]} {$result[2]}" : '未知',
            'code'     => $result[3] ?? '',
            'status'   => ($expected && strpos($result[1], $expected) !== false) ? '✔' : '❌'
        ];
    }
}

// 执行测试
$tester = new IpTester();
$customIp = isset($_POST['ip']) ? trim($_POST['ip']) : null;
$results = $tester->runTest($customIp);
?>

<!DOCTYPE html>
<html>
<head>
    <title>IP地理位置查询测试工具</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 2em; }
        .container { max-width: 800px; margin: 0 auto; }
        .test-case { margin: 1em 0; padding: 1em; border: 1px solid #ddd; }
        .success { color: #2ecc71; }
        .fail { color: #e74c3c; }
        form { margin: 2em 0; }
        input[type="text"] { padding: 8px; width: 300px; }
        button { padding: 8px 16px; background: #3498db; color: white; border: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IP地理位置查询测试</h1>
        
        <form method="post">
            <input type="text" name="ip" placeholder="输入IP地址，例如：114.114.114.114" 
                   value="<?= htmlspecialchars($_POST['ip'] ?? '') ?>">
            <button type="submit">立即测试</button>
            <button type="button" onclick="location.href='?'">重置</button>
        </form>

        <?php if (!empty($results)): ?>
            <?php if (isset($results['error'])): ?>
                <div class="test-case fail">
                    错误：<?= $results['error'] ?>
                </div>
            <?php else: ?>
                <?php foreach ((array)$results as $result): ?>
                    <div class="test-case">
                        <h3>测试IP：<?= $result['ip'] ?></h3>
                        <p>原始数据：<?= implode(' / ', $result['raw_data']) ?></p>
                        <p>解析结果： 
                            <span class="<?= $result['status'] === '✔' ? 'success' : 'fail' ?>">
                                <?= $result['location'] ?> 
                                <?= $result['status'] ?>
                            </span>
                        </p>
                        <p>行政区划码：<?= $result['code'] ?></p>
                    </div>
                <?php endforeach; ?>
                
                <?php if (!$customIp): ?>
                    <div class="stats">
                        <h3>统计信息</h3>
                        <?php
                        $total = count($results);
                        $passed = count(array_filter($results, fn($r) => $r['status'] === '✔'));
                        ?>
                        <p>总测试用例：<?= $total ?> 个</p>
                        <p>通过率：<?= number_format(($passed/$total)*100, 2) ?>%</p>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        <?php endif; ?>
    </div>
</body>
</html>
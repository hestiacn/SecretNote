<?php
class InstallI18n {
    private static $currentLang = 'en_US';
    private static $translations = [];
    private static $fallbackLang = 'en_US';

    public static function init() {
        if (session_status() === PHP_SESSION_NONE) {
            session_start([
                'cookie_secure' => isset($_SERVER['HTTPS']),
                'cookie_httponly' => true,
                'cookie_samesite' => 'Strict'
            ]);
        }
        
        $lang = self::detectLanguage();
        self::loadLanguage($lang);
        
        error_log("Current Language: " . self::$currentLang);
    }

    private static function detectLanguage(): string {
        $allowed = ['en_US', 'zh_CN', 'ja_JP'];
        
        // 强化参数处理 (支持多种格式)
        if (!empty($_GET['lang'])) {
            $paramLang = strtolower($_GET['lang']);
            $paramLang = str_replace(['-', ' '], '_', $paramLang);
            
            // 转换格式 zh_cn => zh_CN
            $paramLangParts = explode('_', $paramLang);
            if (count($paramLangParts) > 1) {
                $paramLang = $paramLangParts[0] . '_' . strtoupper($paramLangParts[1]);
            }

            if (in_array($paramLang, $allowed)) {
                $_SESSION['install_lang'] = $paramLang;
                session_write_close();
                return $paramLang;
            }
        }

        if (!empty($_SESSION['install_lang'])) {
            return $_SESSION['install_lang'];
        }

        if (!empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $browserLangs = explode(',', $_SERVER['HTTP_ACCEPT_LANGUAGE']);
            $langMap = [
                'zh' => 'zh_CN',
                'en' => 'en_US',
                'ja' => 'ja_JP'
            ];

            foreach ($browserLangs as $lang) {
                $langTag = trim($lang);
                if (strpos($langTag, ';') !== false) {
                    list($langTag) = explode(';', $langTag, 2);
                }
                
                $langTag = str_replace('-', '_', $langTag);
                $langParts = explode('_', $langTag);
                if (count($langParts) > 1) {
                    $langTag = $langParts[0] . '_' . strtoupper($langParts[1]);
                }

                if (in_array($langTag, $allowed)) {
                    return $langTag;
                }

                $primaryLang = strtolower(substr($langTag, 0, 2));
                foreach ($langMap as $prefix => $locale) {
                    if ($primaryLang === $prefix) {
                        return $locale;
                    }
                }
            }
        }

        return self::$fallbackLang;
    }

    public static function getCurrentLang(): string {
        return self::$currentLang;
    }

    private static function loadLanguage(string $lang): void {
        $langDir = __DIR__ . '/lang/';
        
        if (!is_dir($langDir) || !is_readable($langDir)) {
            throw new RuntimeException("Language directory inaccessible: {$langDir}");
        }

        $langFile = $langDir . $lang . '.json';
        $fallbackFile = $langDir . self::$fallbackLang . '.json';

        try {
            if (file_exists($langFile)) {
                // 读取文件并转换编码
                $jsonContent = file_get_contents($langFile);
                if ($jsonContent === false) {
                    throw new RuntimeException("Failed to read: {$langFile}");
                }
                
                // 添加编码检测和转换
                $encoding = mb_detect_encoding($jsonContent, ['UTF-8', 'GBK', 'EUC-JP'], true);
                if ($encoding !== 'UTF-8') {
                    $jsonContent = mb_convert_encoding($jsonContent, 'UTF-8', $encoding);
                }

                $translations = json_decode($jsonContent, true, 512, JSON_THROW_ON_ERROR);
            } else {
                $jsonContent = file_get_contents($fallbackFile);
                $translations = json_decode($jsonContent, true, 512, JSON_THROW_ON_ERROR);
            }

            self::$translations = self::flattenTranslations($translations);
            error_log("Loaded translations: " . print_r(self::$translations, true));
            
        } catch (JsonException $e) {
            error_log("JSON解析失败: " . $e->getMessage());
            throw new RuntimeException("Invalid language file: " . $langFile);
        }
    }

    private static function flattenTranslations(array $array, string $prefix = ''): array {
        $result = [];
        foreach ($array as $key => $value) {
            $newKey = $prefix ? "{$prefix}.{$key}" : $key;
            if (is_array($value)) {
                $result = array_merge($result, self::flattenTranslations($value, $newKey));
            } else {
                $result[$newKey] = $value;
            }
        }
        return $result;
    }

    public static function __(string $key, array $replacements = []): string {
        $text = self::$translations[$key] ?? self::getFallbackText($key);
        
        foreach ($replacements as $placeholder => $value) {
            $text = str_replace("{{$placeholder}}", $value, $text);
        }
        
        return $text;
    }

    private static function getFallbackText(string $key): string {
        $fallbackFile = __DIR__ . '/lang/' . self::$fallbackLang . '.json';
        
        if (!file_exists($fallbackFile)) {
            return "[$key]";
        }
        
        static $fallback;
        if (!$fallback) {
            $jsonContent = file_get_contents($fallbackFile);
            $fallback = json_decode($jsonContent, true);
        }
        
        return $fallback[$key] ?? "[$key]";
    }
}

function __(string $key, array $replacements = []): string {
    return InstallI18n::__($key, $replacements);
}

InstallI18n::init();
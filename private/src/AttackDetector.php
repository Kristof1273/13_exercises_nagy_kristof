<?php

declare(strict_types=1);

/**
 * Flags request parameters that look like SQL injection or XSS attempts and
 * writes them to the security log (Exercise 07).
 *
 * DETECTION ONLY — it never blocks. The actual protection is elsewhere
 * (prepared statements, output encoding). Pattern lists are easy to bypass
 * and produce false positives ("O'Brien", "Rock & Roll; select a song"), so
 * blocking on them would annoy real users while barely slowing attackers.
 * Their value is visibility: someone probing the site shows up in the log.
 */
final class AttackDetector
{
    /** Never inspected (and therefore never logged): secrets and tokens. */
    private const SKIP_FIELDS = [
        'csrf_token', 'password', 'password_confirm',
        'current_password', 'new_password', 'new_password_confirm',
    ];

    private const MAX_FIELDS = 100;

    private const SQLI_RULES = [
        // ' OR ...   " AND ...   ') OR ...
        'quote_then_boolean' => '/[\'"`]\s*\)*\s*(?:or|and|xor|\|\||&&)\s+[\w\'"(]/i',
        // OR 1=1   or 'a'='a   AND x LIKE x
        'tautology' => '/\b(?:or|and)\s+[\'"]?(\w+)[\'"]?\s*(?:=|like)\s*[\'"]?\1\b/i',
        'union_select' => '/\bunion\b(?:\s+all)?[\s\/*]+select\b/i',
        // '--   '#   '/*  (closing the string, commenting out the rest)
        'quote_then_comment' => '/[\'"`]\s*(?:--|#|\/\*)/',
        'stacked_query' => '/;\s*(?:select|insert|update|delete|drop|alter|create|truncate|attach|pragma)\b/i',
        'time_based' => '/\b(?:sleep|benchmark|pg_sleep|randomblob)\s*\(|\bwaitfor\s+delay\b/i',
        'schema_probe' => '/\b(?:information_schema|sqlite_master|sqlite_schema|pg_catalog)\b/i',
    ];

    private const XSS_RULES = [
        'script_tag' => '/<\s*\/?\s*script\b/i',
        'event_handler' => '/\bon[a-z]{3,}\s*=/i',
        'javascript_uri' => '/\bjavascript\s*:/i',
        'dangerous_tag' => '/<\s*(?:iframe|svg|img|object|embed|math|base|meta|link|style)\b/i',
    ];

    public static function inspectRequest(): void
    {
        $count = 0;
        foreach (['GET' => $_GET, 'POST' => $_POST] as $source => $params) {
            foreach (self::flatten($params) as $field => $value) {
                if (++$count > self::MAX_FIELDS) {
                    return;
                }
                self::inspect($source, $field, $value);
            }
        }
    }

    private static function inspect(string $source, string $field, string $value): void
    {
        $baseField = (string) preg_replace('/\[.*$/', '', $field);
        if ($value === '' || in_array($baseField, self::SKIP_FIELDS, true)) {
            return;
        }

        // Also look at a once-more-decoded copy (double URL encoding, HTML entities).
        $candidates = array_unique([$value, html_entity_decode(rawurldecode($value), ENT_QUOTES | ENT_HTML5, 'UTF-8')]);

        $sqli = self::matchRules(self::SQLI_RULES, $candidates);
        if ($sqli !== []) {
            SecurityLogger::alert('SQLI_ATTEMPT', 'Input contains SQL injection patterns', [
                'source' => $source, 'field' => $field, 'rules' => $sqli, 'value' => $value,
            ]);
        }

        $xss = self::matchRules(self::XSS_RULES, $candidates);
        if ($xss !== []) {
            SecurityLogger::warning('XSS_ATTEMPT', 'Input contains HTML/JavaScript injection patterns', [
                'source' => $source, 'field' => $field, 'rules' => $xss, 'value' => $value,
            ]);
        }
    }

    /**
     * @param array<string, string> $rules
     * @param array<int, string>    $candidates
     * @return list<string> names of the matching rules
     */
    private static function matchRules(array $rules, array $candidates): array
    {
        $hits = [];
        foreach ($rules as $name => $pattern) {
            foreach ($candidates as $candidate) {
                if (preg_match($pattern, $candidate) === 1) {
                    $hits[] = $name;
                    break;
                }
            }
        }

        return $hits;
    }

    /**
     * Turns nested arrays (a[b][]=1) into "a[b][0]" => "1".
     *
     * @param array<array-key, mixed> $params
     * @return array<string, string>
     */
    private static function flatten(array $params, string $prefix = '', int $depth = 0): array
    {
        $flat = [];
        foreach ($params as $key => $value) {
            $name = $prefix === '' ? (string) $key : $prefix . '[' . $key . ']';
            if (is_array($value) && $depth < 3) {
                $flat += self::flatten($value, $name, $depth + 1);
            } elseif (is_string($value)) {
                $flat[$name] = $value;
            }
        }

        return $flat;
    }
}

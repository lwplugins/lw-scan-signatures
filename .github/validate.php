<?php
/**
 * Self-contained validator for lw-scan-signatures.
 *
 * No Composer / PECL yaml dependency: this repo's signature files follow a
 * small, deliberately restricted YAML subset (flat top-level scalars plus a
 * `tests: {match: [...], no_match: [...]}` block of quoted string lists), so
 * we hand-roll a parser for exactly that subset instead of pulling in a
 * general-purpose YAML library.
 *
 * Checks performed for every signatures/**\/*.yaml file:
 *   - the file parses under our restricted grammar
 *   - id matches ^lw:\d{4,}$ and is unique across the repo
 *   - kind / target / tier / category are one of the allowed values
 *   - pattern is non-empty
 *   - tests.match and tests.no_match are both non-empty
 *   - for kind regex / sql_like_regex: the pattern compiles as PHP PCRE
 *     (wrapped as /pattern/flags, exactly how the backend runs it), every
 *     tests.match string matches it, and every tests.no_match string does not
 *
 * Exits 0 and prints "OK: N signatures" when everything passes, otherwise
 * prints every violation and exits 1.
 */

declare(strict_types=1);

const ALLOWED_KIND = ['regex', 'literal', 'md5', 'sha256', 'sql_like_regex'];
const ALLOWED_TARGET = [
    'file_php', 'file_js', 'file_html', 'file_code', 'file_any',
    'db_post', 'db_option', 'db_trigger', 'htaccess', 'request',
];
const ALLOWED_TIER = ['infected', 'suspicious', 'info'];
const ALLOWED_CATEGORY = [
    'webshell', 'backdoor', 'dropper', 'injector', 'seo_spam', 'redirect',
    'obfuscation', 'uploader', 'mailer', 'defacement', 'credential', 'unknown',
];

/**
 * Unescape a single line of our restricted YAML scalar syntax.
 * Supports: unquoted, 'single quoted' ('' -> ' literal, backslash literal),
 * "double quoted" (\" -> ", \\ -> \, \n -> newline, \t -> tab).
 */
function yaml_unescape_scalar(string $raw): string
{
    $raw = trim($raw);
    if ($raw === '') {
        return '';
    }
    if ($raw[0] === "'" && substr($raw, -1) === "'" && strlen($raw) >= 2) {
        $inner = substr($raw, 1, -1);
        return str_replace("''", "'", $inner);
    }
    if ($raw[0] === '"' && substr($raw, -1) === '"' && strlen($raw) >= 2) {
        $inner = substr($raw, 1, -1);
        $out = '';
        $len = strlen($inner);
        for ($i = 0; $i < $len; $i++) {
            $c = $inner[$i];
            if ($c === '\\' && $i + 1 < $len) {
                $next = $inner[$i + 1];
                switch ($next) {
                    case '"': $out .= '"'; $i++; break;
                    case '\\': $out .= '\\'; $i++; break;
                    case 'n': $out .= "\n"; $i++; break;
                    case 't': $out .= "\t"; $i++; break;
                    default: $out .= $c; // leave backslash as-is for anything else
                }
            } else {
                $out .= $c;
            }
        }
        return $out;
    }
    if ($raw === 'null' || $raw === '~') {
        return '';
    }
    return $raw;
}

/**
 * Parse one signature YAML file under our restricted grammar.
 * Returns an assoc array, or throws a RuntimeException with a human message.
 */
function parse_signature_yaml(string $path): array
{
    $lines = file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        throw new RuntimeException("could not read file");
    }

    $data = [
        'id' => null, 'kind' => null, 'target' => null, 'pattern' => null,
        'flags' => '', 'sql_like' => null, 'tier' => null, 'category' => null,
        'name' => null, 'description' => null, 'common_strings' => [],
        'tests' => ['match' => [], 'no_match' => []],
    ];

    $scalarKeys = ['id', 'kind', 'target', 'pattern', 'flags', 'sql_like',
        'tier', 'category', 'name', 'description'];

    $i = 0;
    $n = count($lines);
    while ($i < $n) {
        $line = $lines[$i];
        $trimmed = rtrim($line);
        if ($trimmed === '' || ltrim($trimmed)[0] === '#') {
            $i++;
            continue;
        }

        if (preg_match('/^([a-zA-Z_]+):\s?(.*)$/', $trimmed, $m) && $line[0] !== ' ') {
            $key = $m[1];
            $val = $m[2];

            if ($key === 'common_strings') {
                // Only "common_strings: []" is supported/emitted by this repo.
                $data['common_strings'] = [];
                $i++;
                continue;
            }

            if ($key === 'tests') {
                $i++;
                // expect "  match:" then list, "  no_match:" then list
                while ($i < $n) {
                    $sub = $lines[$i];
                    if ($sub === '' || preg_match('/^\s*#/', $sub)) { $i++; continue; }
                    if (!preg_match('/^  (match|no_match):\s*$/', $sub, $mm)) {
                        break; // end of tests block
                    }
                    $listKey = $mm[1];
                    $i++;
                    while ($i < $n && preg_match('/^\s{4}-\s(.+)$/', $lines[$i], $lm)) {
                        $data['tests'][$listKey][] = yaml_unescape_scalar($lm[1]);
                        $i++;
                    }
                }
                continue;
            }

            if (in_array($key, $scalarKeys, true)) {
                $data[$key] = yaml_unescape_scalar($val);
            }
            $i++;
            continue;
        }

        $i++;
    }

    return $data;
}

function find_signature_files(string $root): array
{
    $dir = $root . '/signatures';
    if (!is_dir($dir)) {
        return [];
    }
    $found = [];
    $it = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)
    );
    foreach ($it as $file) {
        if ($file->isFile() && substr($file->getFilename(), -5) === '.yaml') {
            $found[] = $file->getPathname();
        }
    }
    sort($found);
    return $found;
}

// ---- main ----

$root = dirname(__DIR__);
$files = find_signature_files($root);

$errors = [];
$seenIds = [];
$okCount = 0;

if (count($files) === 0) {
    $errors[] = "no signatures/**/*.yaml files found under $root";
}

foreach ($files as $file) {
    $rel = substr($file, strlen($root) + 1);
    $fileErrors = [];

    try {
        $sig = parse_signature_yaml($file);
    } catch (Throwable $e) {
        $errors[] = "$rel: failed to parse: " . $e->getMessage();
        continue;
    }

    $id = $sig['id'] ?? '';
    if (!preg_match('/^lw:\d{4,}$/', (string) $id)) {
        $fileErrors[] = "id '$id' does not match ^lw:\\d{4,}\$";
    } else {
        if (isset($seenIds[$id])) {
            $fileErrors[] = "id '$id' is duplicated (also in {$seenIds[$id]})";
        } else {
            $seenIds[$id] = $rel;
        }
    }

    if (!in_array($sig['kind'], ALLOWED_KIND, true)) {
        $fileErrors[] = "kind '{$sig['kind']}' not in [" . implode(', ', ALLOWED_KIND) . "]";
    }
    if (!in_array($sig['target'], ALLOWED_TARGET, true)) {
        $fileErrors[] = "target '{$sig['target']}' not in [" . implode(', ', ALLOWED_TARGET) . "]";
    }
    if (!in_array($sig['tier'], ALLOWED_TIER, true)) {
        $fileErrors[] = "tier '{$sig['tier']}' not in [" . implode(', ', ALLOWED_TIER) . "]";
    }
    if (!in_array($sig['category'], ALLOWED_CATEGORY, true)) {
        $fileErrors[] = "category '{$sig['category']}' not in [" . implode(', ', ALLOWED_CATEGORY) . "]";
    }
    if ($sig['pattern'] === null || $sig['pattern'] === '') {
        $fileErrors[] = "pattern is empty";
    }
    if (empty($sig['tests']['match'])) {
        $fileErrors[] = "tests.match is empty";
    }
    if (empty($sig['tests']['no_match'])) {
        $fileErrors[] = "tests.no_match is empty";
    }

    if (in_array($sig['kind'], ['regex', 'sql_like_regex'], true) && $sig['pattern']) {
        $flags = $sig['flags'] ?? '';
        $delimited = '/' . $sig['pattern'] . '/' . $flags;
        set_error_handler(function () {}); // silence compile warnings, we check return value
        $compiled = @preg_match($delimited, '');
        restore_error_handler();
        if ($compiled === false) {
            $fileErrors[] = "pattern does not compile as PCRE: $delimited";
        } else {
            foreach ($sig['tests']['match'] as $s) {
                $r = @preg_match($delimited, $s);
                if ($r !== 1) {
                    $fileErrors[] = "tests.match string does not match pattern: " . json_encode($s);
                }
            }
            foreach ($sig['tests']['no_match'] as $s) {
                $r = @preg_match($delimited, $s);
                if ($r !== 0) {
                    $fileErrors[] = "tests.no_match string unexpectedly matches pattern: " . json_encode($s);
                }
            }
        }
    }

    if (count($fileErrors) > 0) {
        foreach ($fileErrors as $fe) {
            $errors[] = "$rel: $fe";
        }
    } else {
        $okCount++;
    }
}

if (count($errors) > 0) {
    fwrite(STDERR, "FAILED: " . count($errors) . " violation(s) across " . count($files) . " file(s)\n");
    foreach ($errors as $e) {
        fwrite(STDERR, " - $e\n");
    }
    exit(1);
}

echo "OK: $okCount signatures\n";
exit(0);

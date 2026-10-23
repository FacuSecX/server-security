<?php
/* Server Security Monitor v3.0: compatibility only for this legacy Zone FPM pool. */
if (!function_exists('mail')) { function mail(...$args) { return false; } }
if (!function_exists('get_magic_quotes_gpc')) { function get_magic_quotes_gpc() { return false; } }
if (!function_exists('eregi')) {
    function eregi($pattern, $string, &$matches = null) { return preg_match('~'.str_replace('~', '\\~', $pattern).'~i', $string, $matches); }
}
if (!function_exists('split')) {
    function split($pattern, $string, $limit = -1) { return preg_split('~'.str_replace('~', '\\~', $pattern).'~', $string, $limit); }
}
function zone_legacy_connection($connection = null) {
    if ($connection instanceof mysqli) return $connection;
    if (isset($GLOBALS['zone_legacy_db'])) return $GLOBALS['zone_legacy_db'];
    require '/var/www/server-monitor-zone/kev/pdo.php';
    mysqli_report(MYSQLI_REPORT_OFF);
    $db = mysqli_connect($ip_mysql, $user_sa, $password_sa, $nombre_db);
    if (!$db) throw new RuntimeException('No se pudo conectar a la base de Zone.');
    mysqli_set_charset($db, 'utf8mb4');
    return $GLOBALS['zone_legacy_db'] = $db;
}
if (!function_exists('mysql_connect')) {
    function mysql_connect($host = null, $user = null, $password = null) { mysqli_report(MYSQLI_REPORT_OFF); return $GLOBALS['zone_legacy_db'] = mysqli_connect($host, $user, $password); }
    function mysql_select_db($database, $connection = null) { return mysqli_select_db(zone_legacy_connection($connection), $database); }
    function mysql_query($sql, $connection = null) { return mysqli_query(zone_legacy_connection($connection), $sql); }
    function mysql_real_escape_string($text, $connection = null) { return mysqli_real_escape_string(zone_legacy_connection($connection), (string)$text); }
    function mysql_num_rows($result) { return $result instanceof mysqli_result ? mysqli_num_rows($result) : 0; }
    function mysql_fetch_assoc($result) { return $result instanceof mysqli_result ? mysqli_fetch_assoc($result) : false; }
    function mysql_fetch_array($result, $mode = MYSQLI_BOTH) { return $result instanceof mysqli_result ? mysqli_fetch_array($result, $mode) : false; }
    function mysql_error($connection = null) { return mysqli_error(zone_legacy_connection($connection)); }
}

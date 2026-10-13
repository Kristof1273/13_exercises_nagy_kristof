<?php

declare(strict_types=1);

/**
 * Builds the command line for PHP's built-in web server.
 *
 * Every directive from the project's php.ini is passed with -d instead of
 * using `-c php.ini`. Reason: -c REPLACES the system php.ini, which on many
 * installations (Windows/XAMPP, Arch, ...) is where extensions such as
 * pdo_sqlite or openssl are enabled. With -d the system php.ini still loads
 * and our hardening is layered on top of it. php.ini stays the single source
 * of truth.
 *
 * @return list<string>
 */
function dev_server_command(string $projectRoot, string $host, int $port): array
{
    $iniFile = $projectRoot . '/php.ini';
    $directives = parse_ini_file($iniFile, false, INI_SCANNER_RAW);
    if ($directives === false) {
        throw new RuntimeException("Cannot parse {$iniFile}");
    }

    $command = [PHP_BINARY];
    foreach ($directives as $name => $value) {
        $command[] = '-d';
        $command[] = $name . '=' . $value;
    }

    // Document root = public/  ->  nothing in private/ can ever be requested.
    array_push($command, '-S', "{$host}:{$port}", '-t', $projectRoot . '/public');

    return $command;
}

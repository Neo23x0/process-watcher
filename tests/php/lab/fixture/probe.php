<?php
// Benign probe for the process-watcher PHP lab (tests/php).
//
// It runs FIXED, harmless programs selected by a mode name. Only sizes and counts come from the request
// (n); a command is never taken from the request, so this is not a web shell. Used to produce the process
// shapes an investigation has to deal with: a shell, a direct launch, a long inline command, many
// arguments, awkward characters, a long-running helper and an in-process network connection.
header('Content-Type: text/plain');
$m = isset($_GET['m']) ? $_GET['m'] : 'info';
$n = isset($_GET['n']) ? max(0, min(200000, (int)$_GET['n'])) : 0;

function run_direct(array $argv)
{
    $p = proc_open($argv, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($p)) {
        return "proc_open failed\n";
    }
    $out = stream_get_contents($pipes[1]);
    proc_close($p);
    return $out;
}

switch ($m) {
case 'info':
    echo php_sapi_name(), ' pid=', getmypid(), "\n";
    break;
case 'shell': // PHP hands the string to /bin/sh -c; dash execs the single command in the same PID
    echo shell_exec('uname -s');
    break;
case 'pipe': // sh forks two children
    echo shell_exec('echo pw-pipe | cat');
    break;
case 'deep': // sh -> sh -> uname/id (grandchildren)
    echo shell_exec('sh -c "uname -s; id -u"');
    break;
case 'direct': // array form of proc_open: fork+exec without any shell
    echo run_direct(['/usr/bin/uname', '-s']);
    break;
case 'long': // sh -c 'echo AAAA...': one argument of n+5 bytes
    echo strlen(shell_exec('echo ' . str_repeat('A', $n))), "\n";
    break;
case 'args': // n separate arguments
    echo strlen(run_direct(array_merge(['/bin/echo'], array_map('strval', range(1, max(1, $n)))))), "\n";
    break;
case 'special': // empty, spaces, quotes, newline, tab
    echo run_direct(['/bin/echo', '', 'a b', '"q" \'s\'', "line1\nline2", "tab\tx"]);
    break;
case 'python': // sh -c "python3 -c '...'"
    echo shell_exec("python3 -c 'print(40+2)'");
    break;
case 'phpr': // a PHP CLI interpreter with an inline script
    echo shell_exec("php -r 'echo 6*7;'");
    break;
case 'phpnear': // inline PHP code that starts near the end of the 4096 byte capture: the argument area is 4097 bytes
    echo shell_exec('php -d "x=' . str_repeat('x', 4071) . '" -r ' . "'echo 123456;'");
    break;
case 'bash':
    echo shell_exec("bash -c 'echo pw-bash-ok'");
    break;
case 'bashexec': // bash executes a single command in its own PID: a second exec of the same process
    echo shell_exec("bash -c 'uname -s'");
    break;
case 'helper': // a helper with a distinctive name (copy of sleep) that lives ms milliseconds, for the kill tests
    $ms = isset($_GET['ms']) ? max(1, min(600000, (int)$_GET['ms'])) : 20000;
    $p = proc_open(['/usr/local/bin/pwlab-helper', sprintf('%.3f', $ms / 1000)], [], $pipes);
    echo "helper started\n";
    break;
case 'shellbg': // a shell that lives for ms milliseconds and is not waited for (the shape of a reverse shell)
    $ms = isset($_GET['ms']) ? max(1, min(600000, (int)$_GET['ms'])) : 20000;
    $p = proc_open(['/bin/sh', '-c', 'sleep ' . sprintf('%.3f', $ms / 1000)], [], $pipes);
    echo "shell started\n";
    break;
case 'phpbg': // a PHP CLI interpreter that lives for ms milliseconds, not waited for
    $ms = isset($_GET['ms']) ? max(1, min(600000, (int)$_GET['ms'])) : 20000;
    $p = proc_open(['/usr/bin/php8.4', '-r', 'usleep(' . ($ms * 1000) . ');'], [], $pipes);
    echo "php started\n";
    break;
case 'sockhold': // the connection stays open for a while: visible to the operating system, not to the agent
    $s = @fsockopen('127.0.0.1', 9999, $errno, $errstr, 2);
    if ($s) {
        fwrite($s, "pw-sock-hello\n");
        sleep(3);
        fclose($s);
        echo "connected\n";
    } else {
        echo "no listener: $errstr\n";
    }
    break;
case 'sock': // an outbound connection made by the worker itself: no child process at all
    $s = @fsockopen('127.0.0.1', 9999, $errno, $errstr, 2);
    if ($s) {
        fwrite($s, "pw-sock-hello\n");
        fclose($s);
        echo "connected\n";
    } else {
        echo "no listener: $errstr\n";
    }
    break;
default:
    http_response_code(400);
    echo "unknown mode\n";
}

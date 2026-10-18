<?php
// A benign PHP CLI "queue worker" for the process-watcher PHP lab: runs a few fixed helper programs in a
// loop. Iterations and pause come from the command line, never a command.
$iterations = isset($argv[1]) ? (int)$argv[1] : 5;
$pause_ms = isset($argv[2]) ? (int)$argv[2] : 200;
for ($i = 0; $i < $iterations; $i++) {
    shell_exec('uname -s');
    $p = proc_open(['/bin/true'], [], $pipes);
    proc_close($p);
    usleep($pause_ms * 1000);
}
echo "worker done\n";

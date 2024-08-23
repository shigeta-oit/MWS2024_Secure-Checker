<?php
$URL = htmlspecialchars($_REQUEST['URL']);
file_put_contents(__DIR__ . '/text.txt',$URL . PHP_EOL,FILE_APPEND | LOCK_EX);
require_once 'index.php';
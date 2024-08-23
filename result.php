<?php
$URL = htmlspecialchars($_REQUEST['URL']);
$FILE = htmlspecialchars($_REQUEST['FILE']);
file_put_contents(__DIR__ . '/text.txt',$URL . PHP_EOL,FILE_APPEND | LOCK_EX);
require_once 'index.php';
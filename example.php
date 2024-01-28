<?php

require_once('blackhole.php');

$is_allowed = blackhole();
log_visit($is_allowed);

if(!$is_allowed)
{
	redirect();
	exit;
}


// if(!isset($_GET['rid']) || empty($_GET['rid']))
// {
// 	header("HTTP/1.0 404 Not Found");
// 	exit ("404 Not found");
// }


# If request passes the filters defined in config.php
$base_url = 'https://www.example.org';


$path = $_SERVER['REQUEST_URI'];

$u = $base_url . $path;


header("Location: $u");
exit;
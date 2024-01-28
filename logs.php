<?php
error_reporting(0);

$passwd = 'CHANGE_ME';
if(isset($_GET['k']) && $_GET['k'] === $passwd)
{

	$log_file = realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'd80e86ceec2ee722acfc52a1e2682118.dat';
	$content = file_get_contents($log_file);
	echo nl2br($content);
	exit;
}
else
{
	exit;
}

?>
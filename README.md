# Link Guardian

A simple PHP script for traffic filtering and redirection. Its primary purpose is to protect a webpage/website from bots using pre-defined filters.

Block incoming requests based on:

- Country IP
- Hostname
- Useragent
- Browser
- OS


A request that matches the filters will be redirected to the URL or page specified in the config.php file.


## Usage
1. Edit the configuration file `config.php` and adjust your settings. For accurate results, set the API key for `ipinfo.io`.

2. In your PHP webpage, include the script `blackhole.php` (see `example.php`).


```php

<?php
require_once('blackhole.php');

# Check if the request is allowed
$is_allowed = blackhole();

# Log the request information
log_visit($is_allowed);


# Decide what to do with the request
if(!$is_allowed)
{
	redirect();
	exit;
}




# If request passes the filters defined in config.php
$base_url = 'https://www.example.org';


$path = $_SERVER['REQUEST_URI'];

$u = $base_url . $path;


header("Location: $u");
exit;


```

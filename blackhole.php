<?php
error_reporting(0);

/**
 * Usage: At the top of your PHP scripts, append: require_once('blackhole/blackhole.php');
 * For example:
 * <?php
 * require_once('blackhole/blackhole.php');
 * log_visit(); // Log the request
 * blackhole(); // Check if it passes our filters
 * echo "Checks passed, Welcome!";
 * ?>
 **/

require_once('config.php');
require_once('functions.php');

// returns true if request is allowed, otherwise: false
function blackhole()
{
	# Hint: array($ip, $ua, $request, $protocol, $method, $date, $time, $referer, $hostname);
	$vars = get_request_vars();
	$ip = $vars[0];
	$ua = $vars[1];
	# $request = $vars[2];
	# $protocol = $vars[3];
	# $method = $vars[4];
	# $date = $vars[5];
	# $time = $vars[6];
	$referer = $vars[7];
	$hostname = $vars[8];


	# Check src IP
    if (empty($ip) || $ip === 'Error: Invalid IP Address') {
        return false;
    }


    // Block bad referers
    if ($referer === "1") {
        return false;
    }

    // Block bad hostnames
    if (!empty($hostname) && is_hostname_blacklisted($hostname)) {
        return false;
    }


    // User agent checks
    $is_ua_whitelisted = is_ua_whitelisted($ua);

    if ($is_ua_whitelisted) {
        //
    }
    else
    {
    	if (!isset($ua) || $ua === NULL || strlen($ua) < 10 || is_ua_blacklisted($ua)) {
            return false;
        }
    }

	// # Bots! No accept-lang in the headers..
    // Check Accept-Language header
    $accept_lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_str($_SERVER['HTTP_ACCEPT_LANGUAGE']) : null;
    if (empty($accept_lang) && !$is_ua_whitelisted) {
        return false;
    }

    // Block based on browser and OS
    if (!is_browser_allowed()) {
        return false;
    }

    if (!is_os_allowed()) {
        return false;
    }



    // Get IP information and perform additional checks
    $ip_info = get_ip_info($ip);
    if (!empty($ip_info)) {
        $country = $ip_info['country'];
        $hostname = $ip_info['hostname'];
        $org = $ip_info['org'];


        // Check if the IP is from allowed countries
        if (!empty($country) && !is_country_code_allowed($country)) {
            return false;
        }

        if (!empty($hostname) && is_hostname_whitelisted($hostname)) {
            return true;
        }

        // Double check hostname
        if (!empty($hostname) && is_hostname_blacklisted($hostname)) {
            return false;
        }

        // Double check organization name
        if (!empty($org) && is_hostname_blacklisted($org)) {
            return false;
        }
    }

    return true;
}


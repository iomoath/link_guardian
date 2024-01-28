<?php
error_reporting(0);

# Redirect to somewhere
function redirect($url = NULL)
{
    global $redirect_url;

    if(isset($url) && !empty($url))
    {
       header("Location: $url");
       exit;
    }
    else
    {
        header("Location: $redirect_url");
        exit;
    }
}


function sanitize_str($string) {
    
    $string = trim($string); 
    $string = strip_tags($string);
    #$string = htmlspecialchars($string, ENT_QUOTES, 'UTF-8');
    $string = str_replace("\n", "", $string);
    $string = trim($string); 
    
    return $string;
}


/*
    Name: Simple PHP Browser Detection script.
    Version : 18.05
    Author: Linesh Jose
    Url: http://linesh.com
    Donate:  http://linesh.com/make-a-donation/
    github: https://github.com/lineshjose
    Copyright: Copyright (c) 2013 LineshJose.com
    
    Note: This script is free; you can redistribute it and/or modify  it under the terms of the GNU General Public License as published by 
        the Free Software Foundation; either version 2 of the License, or (at your option) any later version.This script is distributed in the hope 
        that it will be useful,    but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
        See the  GNU General Public License for more details.
*/
/* List of popular web browsers ---------- */
function browsers(){
    return array(
        0=> 'Avant Browser','Arora', 'Flock', 'Konqueror','OmniWeb','Phoenix','Firebird','Mobile Explorer', 'Opera Mini','Netscape',
            'Iceweasel','KMLite', 'Midori', 'SeaMonkey', 'Lynx', 'Fluid', 'chimera', 'NokiaBrowser',
            'Firefox','Chrome','MSIE','Internet Explorer','Opera','Safari','Mozilla','trident'
        );
}

/* List of popular web robots ---------- */
function robots(){
    return  array(
        0=> 'GTmetrix','Googlebot', 'Googlebot-Image', 'MSNBot', 'Yahoo! Slurp', 'Yahoo', 'AskJeeves','FastCrawler','InfoSeek Robot', 'Lycos','YandexBot','YahooSeeker','Google Page Speed Insights','X11'
        );  
}

/* List of popular os platforms ---------- */
function platforms(){
    return  array(
        0=> 'iPad', 'iPhone', 'iPod','iOS', 'macOS','tvOS', 'Mac OS X', 'Macintosh', 'Power PC Mac', 'Windows', 'Windows CE',
            'Symbian', 'SymbianOS', 'Symbian S60', 'Ubuntu', 'Debian', 'NetBSD', 'GNU/Linux', 'OpenBSD', 'Android', 'Linux',
            'Mobile','Tablet',
        );  
}

/*
    This function to get the current browser info
    @param $arg : returns current browser property as an array. Eg: platform, name, version,
    @param $agent: it is the $_SERVER['HTTP_USER_AGENT'] value
*/
function get_browser_info($arg='',$agent='')
{
    if(empty($agent) ) {
        $agent = strtolower(sanitize_str($_SERVER['HTTP_USER_AGENT']));
    }
    
    /*----------------------------------------- browser name ---------------------------------------------*/
    $name='';
    foreach( browsers() as $key){
        if(strpos($agent, strtolower(trim($key))) ){    
            $name= trim($key);
            break;  
        }else{
            continue;
        }
    }
    
    /*----------------------------------------- robot name ---------------------------------------------*/
    foreach(robots() as $key){
        if (preg_match("|".preg_quote(strtolower(trim($key)))."|i", $agent)){
            $is_bot = TRUE;
            $name= trim($key);
            break;  
        }else{
            $is_bot = false;
            continue;
        }
    }
    
    
    /*----------------------------------------- Platform ---------------------------------------------*/
    foreach(platforms() as $key){
        if (preg_match("|".preg_quote(trim($key))."|i", $agent)){
            $platform=trim($key);
            break;  
        }else{
            continue;
        }
    }
    
    /*----------------------------------------- Version ---------------------------------------------*/
    $known = array('version',strtolower($name), 'other');
    $pattern = '#(?<browser>' . join('|', $known) .')[/ ]+(?<version>[0-9.|a-zA-Z.]*)#';
    $version=0; 
    if (preg_match_all($pattern,$agent, $matches)) 
    {   
        if (count($matches['browser'])>0)
        {
            if (strripos($agent,"version") < strripos($agent,strtolower($name)) ){  
                $version= $matches['version'][0];
            }else {
                $version= $matches['version'][1];   
            }
        }else{
            $version=0; 
        }
        if ($version==null || $version=="") {$version="?";}
        $version=(int)round((int) $version);
    }
    /*----------------------------------------- Browser Info ---------------------------------------------*/
    $browser['agent']=$agent;
    if($name=='trident'){
        $browser['name']='Internet Explorer';
        $browser['version']='11';
    }elseif(empty($name)){
        $browser['name']='Unknown';
        $browser['version']=0;  
    }else{
        $browser['name']=$name;
        $browser['version']=$version;
    }
    $browser['is_bot']=$is_bot;
    $browser['platform']=$platform;
    
    if($arg){
        return $browser[$arg];
    }else{  
        return $browser;
    }
}

/* 
    This function to validate current browser. this function returns boolian value
    @param $name : browser name
*/
function is_browser($name){
    $name=strtolower(trim($name));
    $curr_brws=strtolower(get_browser_info('name'));
    if($curr_brws==$name){
        return true;
    }else{
        return false;
    }
}

/* 
    This function to validate current browser version. this function returns boolian value
    @param $version: browser version
*/
function is_browser_version($version){
    $version=strtolower(trim($version));
    $curr_version=strtolower(get_browser_info('version'));
    if($version==$curr_version){
        return true;
    }else{
        return false;
    }
}

/* 
    This function to validate current browser platform. this function returns boolian value
    @param $platform: browser platform (OS)
*/
function is_browser_platform($platform){
    $platform=strtolower(trim($platform));
    $curr_platform=strtolower(get_browser_info('platform'));
    if($curr_platform==$platform){
        return true;
    }else if( $platform=='ios' && in_array($curr_platform, array('iphone','ipod','ipad'))){
        return true;
    }else{
        return false;
    }
}

/* 
    This function to validate current browser is a robot. this function returns boolian value
*/
function is_robot(){
    if(get_browser_info('is_bot')){
        return true;
    }else{
        return false;
    }
}


function normalize_ip($ip) {
    
    if (strpos($ip, ':') !== false && substr_count($ip, '.') == 3 && strpos($ip, '[') === false)
    {
        // IPv4 with port (e.g., 123.123.123:80)
        $ip = explode(':', $ip);
        $ip = $ip[0];
    }
    else
    {
        // IPv6 with port (e.g., [::1]:80)
        $ip = explode(']', $ip);
        $ip = ltrim($ip[0], '[');
        
    }
    return $ip;
}


function validate_ip($ip) {
    
    $options  = FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE;
    $filtered = filter_var($ip, FILTER_VALIDATE_IP, $options);
    
     if (!$filtered || empty($filtered))
     {
        
        if (preg_match("/^(([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]).){3}([1-9]?[0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/", $ip))
        {
            return $ip; // IPv4
        }
        elseif (preg_match("/^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$/", $ip))
        { 
            return $ip; // IPv6
        }

        return false;
    }
    return $filtered;
}


function evaluate_ip() {
     
    $ip_keys = array('HTTP_CF_CONNECTING_IP', 'HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_X_REAL_IP', 'HTTP_X_COMING_FROM', 'HTTP_PROXY_CONNECTION', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'HTTP_COMING_FROM', 'HTTP_VIA', 'REMOTE_ADDR');
    
    foreach ($ip_keys as $key) {
        
        if (array_key_exists($key, $_SERVER) === true) {
            
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                
                $ip = trim($ip);
                
                $ip = normalize_ip($ip);
                
                if (validate_ip($ip)) {
                    return $ip;
                }
            }
        }
    }

    return 'Invalid IP Address';
}

function get_ip_addr() {
    
    $ip = evaluate_ip();
    
    if (preg_match('/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/', $ip, $ip_match))
    {
        $ip = $ip_match[1];
    }
    
    return sanitize_str($ip);
}


function get_referrer()
{
    $ref = isset($_SERVER["HTTP_REFERER"])    ? sanitize_str($_SERVER["HTTP_REFERER"])    : null;
    return $ref;
}

function get_OS()
{
    $browser_info = get_browser_info();
    return $browser_info['platform'];
}

function get_browser_name()
{
    $browser_info = get_browser_info();
    return $browser_info['name'];   
}



function log_visit($is_allowed)
{
    global $log_file_path;


    $ip = get_ip_addr();
    $hostname = gethostbyaddr($ip);
    $referer = get_referrer();
    $req_method   = isset($_SERVER['REQUEST_METHOD'])  ? sanitize_str($_SERVER['REQUEST_METHOD'])  : null;
    $useragent = sanitize_str($_SERVER['HTTP_USER_AGENT']);
    $browser = get_browser_name();
    $os = get_OS();
    $accept_lang = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? sanitize_str($_SERVER['HTTP_ACCEPT_LANGUAGE']) : null;
    $uri = isset($_SERVER['REQUEST_URI']) ? sanitize_str($_SERVER['REQUEST_URI']) : null;
    $protocol = isset($_SERVER['SERVER_PROTOCOL']) ? sanitize_str($_SERVER['SERVER_PROTOCOL']) : null;

    $method = (file_exists($log_file_path)) ? 'a' : 'w';
    $file = fopen($log_file_path, $method);

    $action = "BLOCK";

    if($is_allowed)
    {
        $action = "ALLOW";
    }


    $data = "$ip | ";
    $data .= "$hostname | ";
    $data .=  date("d/m/Y")." ".date("h:i:sa") . " | ";
    $data .= "\"$req_method $uri $protocol\"" . " | ";
    $data .= "$useragent | ";
    $data .= "$referer | ";
    $data .= "$browser | ";
    $data .= "$os | ";
    $data .= "$accept_lang | ";
    $data .= "action=$action";
    $data .= "\n";
    fwrite($file, $data);
    fclose($file);
}



function get_request_vars() {
    
    $ip = get_ip_addr();

    $ua       = isset($_SERVER['HTTP_USER_AGENT']) ? sanitize_str($_SERVER['HTTP_USER_AGENT']) : null;
    $request  = isset($_SERVER['REQUEST_URI'])     ? sanitize_str($_SERVER['REQUEST_URI'])     : null;
    $protocol = isset($_SERVER['SERVER_PROTOCOL']) ? sanitize_str($_SERVER['SERVER_PROTOCOL']) : null;
    $method   = isset($_SERVER['REQUEST_METHOD'])  ? sanitize_str($_SERVER['REQUEST_METHOD'])  : null;
    $referer  = isset($_SERVER["HTTP_REFERER"])    ? sanitize_str($_SERVER["HTTP_REFERER"])    : null;
    $hostname = isset($_SERVER['REMOTE_HOST'])     ? sanitize_str($_SERVER['REMOTE_HOST'])     : null;

    date_default_timezone_set('UTC');

    $date = date('l, F jS Y @ H:i:s');

    $time = time();

    return array($ip, $ua, $request, $protocol, $method, $date, $time, $referer, $hostname);
}



function get_ip_info($ip)
{
    try {
        $url = IPINFO_API_URL . $ip . "?token=" . IPINFO_API_KEY;
        $ip_info_json = file_get_contents($url);


        if($ip_info_json !== NULL)
        {
            $ip_info = json_decode($ip_info_json, true);
            return $ip_info;
        }

        return NULL;
    } catch (Exception $e) {
        return NULL;
    }
}


# Check if the User-agent is blacklisted
function is_ua_blacklisted($ua)
{
    global $ua_blacklist;

    if (preg_match($ua_blacklist, $ua))
    {
        return true;
    }
    
    return false;
}

# Check if the User-agent is whitelisted
function is_ua_whitelisted($ua)
{
    global $ua_whitelist;

    if (preg_match($ua_whitelist, $ua))
    {
        return true;
    }
    
    return false;
}


# Check if the Hostname is blacklisted
function is_hostname_blacklisted($hostname)
{
    global $hostname_blacklist;

    if (preg_match($hostname_blacklist, $hostname))
    {
        return true;
    }
    
    return false;
}


# Check if the hostname is whitelisted
function is_hostname_whitelisted($hostname)
{
    global $hostname_whitelist;

    if (preg_match($hostname_whitelist, $hostname))
    {
        return true;
    }
    
    return false;
}


function is_country_code_allowed($countryCode)
{
    global $allowed_countries;

    if (in_array($countryCode, $allowed_countries))
    {
        return true;
    }

    return false;
}


function is_browser_allowed()
{
    global $browser_blacklist;

    $browser_name = get_browser_name();

    if (in_array($browser_name, $browser_blacklist))
    {
        return false;
    }

    return true;
}


function is_os_allowed()
{
    global $os_blacklist;

    $os_Name = get_OS();

    if (in_array($os_Name, $os_blacklist))
    {
        return false;
    }

    return true;
}
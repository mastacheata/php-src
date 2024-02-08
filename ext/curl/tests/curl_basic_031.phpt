--TEST--
CURLOPT_CAPATH should be set from openssl.capath
--EXTENSIONS--
curl
openssl
--SKIPIF--
<?php
if (!function_exists("proc_open")) die("skip no proc_open");
exec('openssl version', $out, $code);
if ($code > 0) die("skip couldn't locate openssl binary");
if (PHP_OS_FAMILY === 'Windows') die('skip not for Windows');
if (PHP_OS_FAMILY === 'Darwin') die('skip Fails intermittently on macOS');
$curl_version = curl_version();
if ($curl_version['version_number'] < 0x074700) {
    die("skip: blob options not supported for curl < 7.71.0");
}
?>
--INI--
openssl.capath = 'ext/curl/tests/'
openssl.cainfo = 'ext/curl/tests/curl_setopt_ssl_clientcert.pem'
--FILE--
<?php

function check_error(CurlHandle $ch) {
    if (curl_errno($ch) !== 0) {
        echo "CURL ERROR: " . curl_errno($ch) . "\n";
    }
}

function check_response($response, $clientCertSubject) {
    if (strpos($response, $clientCertSubject) === false) {
        echo "client cert subject not in response\n";
    } else {
        echo "client cert subject in response\n";
    }
}

$clientCertSubject = "Subject: C=US, ST=TX, L=Clientlocation, O=Clientcompany, CN=clientname/emailAddress=test@example.com";

// load server cert
$serverCertPath = __DIR__ . DIRECTORY_SEPARATOR . 'curl_setopt_ssl_servercert.pem';
$serverCert = file_get_contents($serverCertPath);

// load server key
$serverKeyPath = __DIR__ . DIRECTORY_SEPARATOR . 'curl_setopt_ssl_serverkey.pem';
$serverKey = file_get_contents($serverKeyPath);

// load client cert
$clientCertPath = __DIR__ . DIRECTORY_SEPARATOR . 'curl_setopt_ssl_clientcert.pem';
$clientCert = file_get_contents($clientCertPath);

if ($serverCert === false
    || $serverKey === false
    || $clientCert === false
    || $clientKey === false
) {
    die('failed to load test certs and keys for files');
}

$port = 14430;

// set up local server
$cmd = "openssl s_server -key $serverKeyPath -cert $serverCertPath -accept $port -www -CAfile $clientCertPath";
$process = proc_open($cmd, [["pipe", "r"], ["pipe", "w"], ["pipe", "w"]], $pipes);

if ($process === false) {
    die('failed to start server');
}
try {
    // Give the server time to start
    sleep(1);

    $ch = curl_init("https://127.0.0.1:$port/");

    echo "Check that CURLOPT_CAPATH is initialized from the openssl.capath php.ini config";
    var_dump(curl_getinfo($ch, CURLINFO_CAPATH) === ini_get('openssl.capath'));
    
    echo "\n";
    echo "Check that CURLOPT_CAINFO is initialized from the openssl.cainfo php.ini config";
    var_dump(curl_getinfo($ch, CURLINFO_CAINFO) === ini_get('openssl.cainfo'));

    echo "\n";
    echo "Make sure the curl.cainfo php.ini config is not set";
    var_dump(ini_get('curl.cainfo'));

    echo "\n";
    echo "Verify the setting is applied correctly and the OpenSSL server's certificate can be verified";
    var_dump(curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true));
    var_dump(curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $response = curl_exec($ch);
    check_response($response, $clientCertSubject);
    check_error($ch);
    curl_close($ch);
} finally {
    // clean up server process
    proc_terminate($process);
    proc_close($process);
}

?>
--EXPECT--
Check that CURLOPT_CAPATH is initialized from the openssl.capath php.ini config
bool(true)

Check that CURLOPT_CAINFO is initialized from the openssl.cainfo php.ini config
bool(true)

Make sure the curl.cainfo php.ini config is not set
bool(false)

Verify the setting is applied correctly and the OpenSSL server's certificate can be verified
bool(true)
bool(true)
client cert subject in response

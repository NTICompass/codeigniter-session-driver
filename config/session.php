<?php  if ( ! defined('BASEPATH')) exit('No direct script access allowed');

/*
|--------------------------------------------------------------------------
| Session Variables
|--------------------------------------------------------------------------
| 'sess_driver'				= session driver to use (cookie, database, native, cache, hybrid)
| 'sess_cache_driver'		= driver to use for cache
|
*/
$config['sess_driver'] = 'hybrid';
$config['sess_cache_driver'] = 'apc';

$config['sess_match_ip'] = true;
$config['sess_match_useragent'] = true;

$config['sess_table_name'] = 'ci_sessions';

$config['sess_cookie_name'] = 'ci_session';
//$config['cookie_lifetime'] = '';
//$config['cookie_path'] = '';
//$config['cookie_domain'] = '';
//$config['cookie_secure'] = '';
//$config['cookie_httponly'] = '';

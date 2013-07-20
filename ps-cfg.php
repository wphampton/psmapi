<?php
/*
 * Configuration variables for PSmAPI
 * Author Wes Hampton 2013
 * Last tested with PowerSchool 7.8
 */
 
//PHP config
//Adjust these for screen scraping techniques
ini_set("pcre.backtrack_limit", "23001337");
ini_set("pcre.recursion_limit", "23001337");

//PowerSchool Site
$PScfg['domain'] = 'your.ps.server'; //ps7.myschool.org

//PowerSchool Admin Credentials
$PScfg['admin_user'] = 'username'; //user with access to PS Admin
$PScfg['admin_pass'] = 'password'; //above user's password

//ODBC Credentials
$PScfg['odbc_user'] = ''; //ODBC username (optional)
$PScfg['odbc_pass'] = ''; //ODBC password (optional)
$PScfg['odbc_dsn'] = ''; //DSN name (optional)

//Specific URLS and pages used throughout PSmAPI (Don't change these)
$PScfg['protocol'] = 'https'; //http or https
$PScfg['ps_base_url'] = "{$PScfg['protocol']}://{$PScfg['domain']}";
$PScfg['admin_prompt_url'] = "{$PScfg['ps_base_url']}/admin/pw.html";
$PScfg['admin_login_url'] = "{$PScfg['ps_base_url']}/admin/home.html";
$PScfg['admin_home_url'] = "{$PScfg['ps_base_url']}/admin/home.html";
$PScfg['public_url'] = "{$PScfg['ps_base_url']}/public/home.html";
$PScfg['guardian_query'] = "{$PScfg['ps_base_url']}/admin/guardians/home.html";
$PScfg['pga_add_acct'] = "{$PScfg['ps_base_url']}/admin/guardians/home.html"; // submit page for adding a new PGA
$PScfg['pga_edit_info'] = "{$PScfg['ps_base_url']}/admin/guardians/home.html"; // submit page for modifying PGA personal information
$PScfg['pga_add_stud'] = "{$PScfg['ps_base_url']}/admin/guardians/student_add_dialog.html"; //submit page for adding students to a PGA
$PScfg['pga_del_stud'] = "{$PScfg['ps_base_url']}/admin/success.html"; //submit page for removing students from a PGA
$PScfg['pga_trigger_del_stud'] = "{$PScfg['ps_base_url']}/admin/students/guardian_delete_dialog.html"; //visited prior to removing students from a PGA
$PScfg['pga_trigger_edit_info'] = "{$PScfg['ps_base_url']}/admin/guardians/home.html"; //visited prior to updating personal info for a PGA
$PScfg['pga_trigger_add_acct'] = "{$PScfg['ps_base_url']}/admin/guardians/new_guardian_account.html"; //visited prior to entering a new PGA
$PScfg['pga_change_pwd'] = "{$PScfg['ps_base_url']}/public/userprefpassword.html"; //submit page for changed a PGA page
//$PScfg['pga_trigger_change_pwd'] = "{$PScfg['ps_base_url']}/public/userprefpassword.html"; //not currently necessary, but would be visited prior to changing a PGA password 
$PScfg['custom_stud_screen_post'] = "{$PScfg['ps_base_url']}/admin/changesrecorded.white.html"; //submit page for custom student screens
$PScfg['custom_stud_screen_trigger_post'] = "{$PScfg['ps_base_url']}/admin/students/customscreentemplate.html"; //submit page for custom student screens
$PScfg['stuinfo'] = "{$PScfg['ps_base_url']}/admin/psmapi/stuinfo.html";
$PScfg['pgainfo'] = "{$PScfg['ps_base_url']}/admin/psmapi/pgainfo.html";
$PScfg['pgakids'] = "{$PScfg['ps_base_url']}/admin/psmapi/pgakids.html";
$PScfg['stuparinfo'] = "{$PScfg['ps_base_url']}/admin/psmapi/studemopginfo.html";
$PScfg['stucourseinfo'] = "{$PScfg['ps_base_url']}/admin/psmapi/studcourses.html";
$PScfg['teacherinfo'] = "{$PScfg['ps_base_url']}/admin/psmapi/teachinfo.html";

//--------------------------------------------

//Random Cookie File for this Session
$PScfg['cookie'] = tempnam("/tmp", "PSC");

//Set some timeout values for cURL, in seconds.  Used for CURLOPT_CONNECTTIMEOUT and CURLOPT_TIMEOUT unless overridden in specific functions
$PScfg['curl_timeout'] = 120;

//Default temp password for initial PGA accounts
$PScfg['pga_default_pass'] = 'temppgapass';

//Temporary initial emails used to creating PGAs
$PScfg['pga_tmp_email'] = 'temppgaemail@example.com';

//Default relationship for a parent of a student if a match was not found
$PScfg['pga_default_relation'] = '1310'; //Other

//Custom HTTP headers for HTTP cURL Requests to PowerSchool Interface
//This determines how your program will look to your PowerSchool server
$PScfg['http_headers'] = array(
  "Host: {$PScfg['domain']}",
	"User-Agent: Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.23) Gecko/20110921 Ubuntu/10.04 (lucid) Firefox/3.6.23",
	"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
	"Accept-Language: en-us,en;q=0.5",
	"Accept-Encoding: gzip,deflate",
	"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7",
	"Keep-Alive: 115",
	"Connection: keep-alive",
	"Pragma: no-cache",
	"Cache-Control: no-cache"	
);
?>

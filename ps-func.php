<?php
/*
 * Functions related to communicating with the PowerSchool website in an automated fashion
 * Author Wes Hampton 2013
 * PowerSchool Version 7.8
 */


/*
 * Works on PS 7.0.3
*/
function hex_hmac_md5($key, $data)
{
  //Used in PSmAPI for hashing the login password
	//Derived from: http://www.php.net/manual/en/function.mhash.php#27225

	return bin2hex(mhash(MHASH_MD5, utf8_encode($data), utf8_encode($key)));
}


/*
 * Works on PS 7.0.3
*/
function b64_md5($data) {
    $result = base64_encode(pack('H*', md5(utf8_encode($data))));
    
    //the PowerSchool implementation does not pad B64 values with "=" so we need to remove them.
    return str_replace('=','',$result);
}

/*
* This is NOT USED, however it is a PHP rewrite of the Paul Johnston function of the same name that I wanted to preserve in case for the future.
* Original JavaScript here: http://pajhome.org.uk/crypt/md5/md5.html
*/
function rstr2binl($input)
{
	$output = array_fill(0, (strlen($input) >> 2), 0);
	//print_r($output);
	
	for ($i = 0; $i < (strlen($input) * 8); $i += 8)
	{
		//for some reason sometimes the array should have had an extra value initialized to zero above.  It continues just fine, assuming zeros apparently anyway.
		$output[$i>>5] |= (ord(mb_substr($input, ($i / 8), 1)) & 0xFF) << ($i%32);
	}
	
	return $output;
}


/*
 * Works on PS 7.0.3
*/
function PS_getAdminLogin ()
{
global $PScfg;

/*
 * This function retrieves the PowerSchool Admin Login page
 *
 */

$admin_prompt_url = $PScfg['admin_prompt_url'];
$PScookie = &$PScfg['cookie'];

//initialize the cURL Handle, which we'll pass around to various parts of this script
$ch = curl_init();

//we want this stored in a string, not output directly.
//also we don't want to worry about any SSL errors.
$options = array(
	CURLOPT_URL => $admin_prompt_url,
	CURLOPT_COOKIEJAR => $PScookie,
	CURLOPT_COOKIEFILE => $PScookie,
	CURLOPT_RETURNTRANSFER => true,
	CURLOPT_SSL_VERIFYPEER => false
);

//actualy set the options for the cURL handle
curl_setopt_array($ch, $options);

//store the login page in a string for parsing
$result = curl_exec($ch);

//close connection
curl_close($ch);

return $result;
}


/*
 * Works on PS 7.0.3
 * This function establishes the login session to PowerSchool Admin
*/
function PS_loginAdmin ()
{
$result = false; //we switch this to true if our test for successful login is true

global $PScfg;

$admin_login_url = $PScfg['admin_login_url'];
$admin_user = $PScfg['admin_user'];
$admin_pass = $PScfg['admin_pass'];
$PScookie = &$PScfg['cookie'];
 
//Retrieve the PowerSchool Login page HTML source code
$PSLoginSource = PS_getAdminLogin();

//Parse the PS Login source code for the PSKey and PSToken
$PSSecrets = PS_scrapeSecrets($PSLoginSource);

//set POST variables
$fields = array(
						'username'=>urlencode($admin_user),
						'pstoken'=>urlencode($PSSecrets['pstoken']),
						'request_locale'=>urlencode('en_US'),
						//'password'=>urlencode(hex_hmac_md5($PSSecrets['pskey'],strtolower($admin_pass)))
						'password'=>urlencode(hex_hmac_md5($PSSecrets['pskey'],b64_md5($admin_pass)))
				);
				
//url-ify the data for the POST
$fields_string = '';
foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
rtrim($fields_string,'&');

//open connection
$ch = curl_init();

//set the url, number of POST vars, POST data
curl_setopt($ch,CURLOPT_URL,$admin_login_url);
curl_setopt($ch, CURLOPT_COOKIEJAR, $PScookie);
curl_setopt($ch, CURLOPT_COOKIEFILE, $PScookie);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch,CURLOPT_POST,true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

//execute post
$result = curl_exec($ch);

//close connection
curl_close($ch);

//if cURL attempt was false then we return false, other wise we look at the returned value
//to see if we landed on the home page properly, using the string "Last Sign In:" as the test
$result = ($result !== false && stripos($result, 'Last Sign In:') !== false) ? true : false;

return $result;
}


function PS_loginPublic ()
{
/*
 *
 *
 */
}


/* 
 * Works on PS 7.0.3
 * Provide a $page that this script will request and return" 
*/
function touch_ps_page($url)
{
	global $PScfg;
	
	$ps_touch_url = $url;
	$PScookie = &$PScfg['cookie'];

	//initialize the cURL Handle, which we'll pass around to various parts of this script
	$ch = curl_init();
	
	$options = array(
		CURLOPT_URL => $ps_touch_url,
		CURLOPT_COOKIEJAR => $PScookie,
		CURLOPT_COOKIEFILE => $PScookie,
		CURLOPT_FOLLOWLOCATION => true,
		CURLOPT_RETURNTRANSFER => true,
		CURLOPT_SSL_VERIFYPEER => false
	);
	
	//actualy set the options for the cURL handle
	curl_setopt_array($ch, $options);
	
	//store the login page in a string for parsing
	$result = curl_exec($ch);
	
	//close connection
	curl_close($ch);
	
	return $result;
}



/* Works on PS 7.0.3
 * Based on PS Version: 6.2.2.0.0108 the response from the server should be a string of "success " on success,
 *	in that case we'll return bool true from this function, or false on any other value 
 * $scrn should be an integer value from the URL of the custom screen, screenid
 * $stud should be the student's DCID from the student table in PowerSchool
 * $data should be an array of key/value pairs where the key is the field number from the custom form (ex. "379" from the input field UF-0013792485) 
 * and the value is the desired data.  This function will add the "UF-", the "001" (Student Table) and the DCID.  
*/
function PS_SubmitCustomStudScreen($scrn, $stud, $data)
{
global $PScfg;

$result = false;
$domain = $PScfg['domain'];
$cookie = &$PScfg['cookie'];

//first we want to visit the proper page to trigger ?something? on the server side code or else this process will fail.
$url = $PScfg['custom_stud_screen_trigger_post'] . "?frn=001" . $stud . "&screenid=" . $scrn;
touch_ps_page($url);

//set POST variables
$url = $PScfg['custom_stud_screen_post'];
$fields = array(
						'ac'=>urlencode('prim')
				);

//add the custom data to the fields
foreach ($data as $key => $value)
{
	$fields['UF-001'.$key.$stud] = urlencode($value);
}

//url-ify the data for the POST
$fields_string = '';
foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
$fields_string = rtrim($fields_string,'&');

//add some more headers to the default
$headers = array_merge($PScfg['http_headers'],array(
	"X-Requested-With: XMLHttpRequest",
	"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
	"Content-Length: " . strlen($fields_string),
	)
);

//open connection
$ch = curl_init();

//set the url, number of POST vars, POST data
curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

//execute post
$result = curl_exec($ch);

//close connection
curl_close($ch);

//really an ODBC call can be make here to make sure this data was actually saved properly.

//return true/false if data was sent to server successfully
return ($result !== false) ? true : false;
}


function PS_PGAaddStuds($gai, $studAry, $relAry)
{
/* Based on PS Version: 6.2.2.0.0108 the response from the server should be a string of "success " on success,
	in that case we'll return bool true from this function, or false on any other value */
global $PScfg;

$result = false;
$domain = $PScfg['domain'];
$cookie = &$PScfg['cookie'];
$studID = implode(',',$studAry);
$PGAgai = $gai;
$PGArel = implode(',',$relAry);

//set POST variables
$url = $PScfg['pga_add_stud'];
$fields = array(
						'selectedGuardianRelationshipsForStudents'=>urlencode($PGArel),
						'selectedStudentDcids'=>urlencode($studID),
						'gai'=>urlencode($PGAgai),
						'submitOperation'=>urlencode('add')
				);

//url-ify the data for the POST
$fields_string = '';
foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
$fields_string = rtrim($fields_string,'&');

//add some more headers to the default
$headers = array_merge($PScfg['http_headers'],array(
	"X-Requested-With: XMLHttpRequest",
	"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
	"Content-Length: " . strlen($fields_string),
	)
);

//open connection
$ch = curl_init();

//set the url, number of POST vars, POST data
curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

//execute post
$result = curl_exec($ch);

//close connection
curl_close($ch);

//really an ODBC call can be make here to make confirm these student are added. 

//return true/false
return (trim($result) == 'success') ? true : false;
}


function PS_PGAdelStuds($gai, $studID)
{
/* Based on PS Version: 7.10 the response from the server should be a form to change student access info on success, 
this function will return bool true in this case, false on fail. */
global $PScfg;

$result = false;
$domain = $PScfg['domain'];
$cookie = &$PScfg['cookie'];
$studID = $studID;
$PGAgai = $gai;

//first we want to visit the proper page to trigger ?something? on the server side code or else this process will fail.
$url = $PScfg['pga_trigger_del_stud'] . '?gai=' . urlencode($gai) . '&studentId=' . urlencode($studID) . '&guardianPortal=true';
touch_ps_page($url);

//set POST variables
$url = $PScfg['pga_del_stud'];
$fields = array(
						'ac'=>urlencode('brij:admin-accountmanagement-pkg/DeleteGuardianFromStudent'),
						'doc'=>urlencode('/admin/students/guardian_delete_dialog.html'),
						'render_in_java'=>urlencode('true'),
						'gai'=>urlencode($PGAgai),
						'studentId'=>urlencode($studID)
				);

//url-ify the data for the POST
$fields_string = '';
foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
$fields_string = rtrim($fields_string,'&');

//add some more headers to the default
$headers = array_merge($PScfg['http_headers'],array(
	"X-Requested-With: XMLHttpRequest",
	"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
	"Content-Length: " . strlen($fields_string),
	)
);

//open connection
$ch = curl_init();

//set the url, number of POST vars, POST data
curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

//execute post
$result = curl_exec($ch);

//close connection
curl_close($ch);

//really an ODBC call can be made here to make confirm this student is removed. 
//right now we'll just do a screen scrape to see if the result appears normal

//return true/false
return (strpos($result, 'brij:admin-accountmanagement-pkg/UpdateGuardianWebId') !== false) ? true : false;
}


function PS_PGAadd(&$dbh, $first, $last, $email, $username, $locked = false, $pass = '')
{
/* Based on PS Version: 6.2.2.0.0108 the response from the server should be a blank page on success.
this function returns true/false after executing an ODBC query to see if account exists at the end
It needs the database connection because it makes a call to see if there is an account with this username or email already */
global $PScfg;

$result = false;
$domain = $PScfg['domain'];
$cookie = &$PScfg['cookie'];
$PGAfirst = $first;
$PGAlast = $last;
$PGAemail = $email;
$PGAuser = $username;
$PGAlocked = $locked;
$PGApass = ($pass != '') ? $pass : $PScfg['pga_default_pass'];

//let's make sure this email address or username is not currently being used first
//in the sequence of main script we are actually sending a temporary email address, so this only check what this function receives.
if ((PS_getPGAbyUsername($dbh, $PGAuser) === false) && (PS_getPGAbyEmail($dbh, $PGAemail) === false))
{
	//first we want to visit the proper page to trigger ?something? on the server side code or else this process will fail.
	$url = $PScfg['pga_trigger_add_acct'];
	touch_ps_page($url);
	
	//set POST variables
	$url = $PScfg['pga_add_acct'];
	$fields = array(
							'ac'=>urlencode('brij:admin-accountmanagement-pkg/submitAdminNoStudentsGuardianAccountForm'),
							'doc'=>urlencode('/admin/guardians/new_guardian_account.html'),
							'render_in_java'=>urlencode('true'),
							'newGuardian.firstName'=>urlencode($PGAfirst),
							'newGuardian.lastName'=>urlencode($PGAlast),
							'newGuardian.email'=>urlencode($PGAemail),
							'accountInfo.username'=>urlencode($PGAuser),
							'accountInfo.password'=>urlencode($PGApass),
							'passwordConfirm'=>urlencode($PGApass)
					);
			
		
	//add a POST value if the account should be locked
	if ($locked) $fields['accountLocked'] = urlencode('true');
	
	//url-ify the data for the POST
	$fields_string = '';
	foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
	$fields_string = rtrim($fields_string,'&');
	
	//add some more headers to the default
	$headers = array_merge($PScfg['http_headers'],array(
		"X-Requested-With: XMLHttpRequest",
		"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
		"Content-Length: " . strlen($fields_string),
		)
	);
	
	//open connection
	$ch = curl_init();
	
	//set the url, number of POST vars, POST data
	curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
	curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
	curl_setopt($ch,CURLOPT_URL,$url);
	curl_setopt($ch,CURLOPT_POST,true);
	curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	
	//execute post
	$result = curl_exec($ch);
	
	//close connection
	curl_close($ch);
	
	//if the data appeared to be sent properly then we should now find this record in the database
	$result = ($result !== false && PS_getPGAbyUsername($dbh, $PGAuser) !== false) ? true : false;
}

return ($result !== false) ? true : false;
}


function PS_PGAedit(&$dbh, $gai, $first, $last, $email, $username, $locked = false, $pass = '')
{
	/* Based on PS Version: 6.2.2.0.0108 the response from the server should be a blank page on success, 
	this function will return bool true in this case, false on fail. 
	It needs the database connection because it makes a call to get and compare the original information to confirm success */
	global $PScfg;
	
	$result = false;
	$domain = $PScfg['domain'];
	$cookie = &$PScfg['cookie'];
	$PGAgai = $gai;
	$PGAfirst = $first;
	$PGAlast = $last;
	$PGAemail = $email;
	$PGAuser = $username;
	$PGAlocked = $locked;
	$PGApass = $pass;
	$needs_pass_update = ($PGApass != '') ? true : false; 
	
	//it's possible that this is a new username, and in that case we need to know what the old one was
	//either way it is probably a good idea to make sure this parent exists anyway or return false on error
	$pgaOrig = PS_getPGAbyActID($dbh, $PGAgai);
	
	if ($pgaOrig)
	{
		$pgaUserOrig = $pgaOrig['USERNAME'];
		$pgaModPCAS = $pgaOrig['MOD_PCAS'];
			
		//first we want to visit the proper page to trigger ?something? on the server side code or else this process will fail.
		$url = $PScfg['pga_trigger_edit_info'] . '?gai=' . urlencode($gai);
		touch_ps_page($url);
		
		//set POST variables
		$url = $PScfg['pga_edit_info'];
		$fields = array(
								'ac'=>urlencode('brij:admin-accountmanagement-pkg/SaveGuardianAccount'),
								'doc'=>urlencode('/admin/guardians/home.html'),
								'render_in_java'=>urlencode('true'),
								'gai'=>urlencode($PGAgai),
								'account.username'=>urlencode($pgaUserOrig),
								'firstName'=>urlencode($PGAfirst),
								'lastName'=>urlencode($PGAlast),
								'email'=>urlencode($PGAemail),
								'username'=>urlencode($PGAuser),
								'newPassword'=>urlencode($PGApass),
								'confirmPassword'=>urlencode($PGApass)
						);
				
			
		//add a POST value if the account should be locked
		if ($locked) $fields['accountDisabled'] = urlencode('true');
		
		//url-ify the data for the POST
		$fields_string = '';
		foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
		$fields_string = rtrim($fields_string,'&');
		
		//add some more headers to the default
		$headers = array_merge($PScfg['http_headers'],array(
			"X-Requested-With: XMLHttpRequest",
			"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
			"Content-Length: " . strlen($fields_string),
			)
		);
		
		//open connection
		$ch = curl_init();
		
		//set the url, number of POST vars, POST data
		curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
		curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
		curl_setopt($ch,CURLOPT_URL,$url);
		curl_setopt($ch,CURLOPT_POST,true);
		curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		
		//execute post
		$result = curl_exec($ch);
		
		//close connection
		curl_close($ch);
		
		//as long as the data appeared to be successfully sent to the server we now verify against the database
		if ($result !== false)
		{
			$pgaConfirm = PS_getPGAbyActID($dbh, $PGAgai);
			$isConfirmed = false; //we set this to true if everything now matches
								
			//set up some simple variables from the matching PGA
			$pgaFirstConfirm = $pgaConfirm['FIRSTNAME'];
			$pgaLastConfirm = $pgaConfirm['LASTNAME'];
			$pgaEmailConfirm = $pgaConfirm['EMAIL'];
			$pgaUserConfirm = $pgaConfirm['USERNAME'];
			$pgaCredEncConfirm = $pgaConfirm['ENCRYPTIONMODE']; //For PS7 changed from ISCREDENTIALENC TO ENCRYPTIONMODE
			$pgaModPCASConfirm = $pgaConfirm['MOD_PCAS'];
			
			//make sure record date changed and compare database fields to what was submitted to server, test password update separately if necessary below
			$isConfirmed = ($pgaModPCASConfirm != $pgaModPCAS && $pgaFirstConfirm == $PGAfirst && $pgaLastConfirm == $PGAlast && $pgaEmailConfirm == $PGAemail && $pgaUserConfirm == $PGAuser) ? true : false;
			
			//check if it really appeared to reset the credentials (if it was required)
			//***specifically check if creds are set as expired which means they are ready to be changed by the user (or us via script/function)
			//the pcas_account.credentialchangeddate field only changes is the value changed, which in certain repair/maintenance situations might not be the case
			//a simple test if creds are different then the ones we got only moments ago is not sufficient because they could possibly
			//have just been "reset" to the value they already were.
			$isConfirmed = ($isConfirmed && (!$needs_pass_update || ($needs_pass_update && $pgaCredEncConfirm == 2))) ? true : false;
			
			//set the result to true/false as determined by our confirmation tests directly above
			$result = $isConfirmed;
		}
	
	} //end testing for existing account
	
	return $result;
}


function PS_PGAchangePwd(&$PSdbh, &$AUXdbh, $user, $oldPwd, $newPwd)
{
/* Based on PS Version: 6.2.2.0.0108 the response from the server should be a blank page on success, 
this function will return bool true in this case, false on fail. 
Also, this function doesn't need a login or cookies, just need to know the existing password. 
It does however use an ODBC connection to make sure the change took effect! 

$PSdbh is the ODBC connection to the PowerSchool database
$AUXdbh is the connection to the database server holding the ps_parent table for updating the password hash
*/
global $PScfg;

$result = false;
$domain = $PScfg['domain'];
$PGAuser = $user;
$PGAoldPwd = $oldPwd;
$PGAnewPwd = $newPwd;

//get the current account details for this user so we can know if it has changed the password at the end of the procedure
$parInfo = PS_getPGAbyUsername($PSdbh, $PGAuser);

if ($parInfo !== false)
{
	$preModCred = $parInfo['MOD_CRED'];
	
	//first we want to visit the proper page to trigger ?something? on the server side code or else this process will fail.
	//the trigger is unnecesary for this function
	//$url = $PScfg['pga_trigger_change_pwd'] . '?credExpired=1&userName=$user';
	//touch_ps_page($url);
	
	//set POST variables
	$url = $PScfg['pga_change_pwd'];
	$fields = array(
							'ac'=>urlencode('brij:public-parentaccess-pkg/SubmitChangePasswordForm'),
							'doc'=>urlencode('/public/userprefpassword.html'),
							'render_in_java'=>urlencode('true'),
							'userType'=>urlencode('guardian'),
							'userName'=>urlencode($PGAuser),
							'credExpired'=>urlencode('2'),
							'currentCredential'=>urlencode($PGAoldPwd),
							'newCredential'=>urlencode($PGAnewPwd),
							'newCredential1'=>urlencode($PGAnewPwd)
					);
			
	//url-ify the data for the POST
	$fields_string = '';
	foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
	$fields_string = rtrim($fields_string,'&');
	
	//add some more headers to the default
	$headers = array_merge($PScfg['http_headers'],array(
		"X-Requested-With: XMLHttpRequest",
		"Content-Type: application/x-www-form-urlencoded; charset=UTF-8",
		"Content-Length: " . strlen($fields_string),
		)
	);
	
	//open connection
	$ch = curl_init();
	
	//set the url, number of POST vars, POST data
	curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
	curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
	curl_setopt($ch,CURLOPT_URL,$url);
	curl_setopt($ch,CURLOPT_POST,true);
	curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
	curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
	curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
	
	//execute post
	$result = curl_exec($ch);
	
	//close connection
	curl_close($ch);
	
	//if the data seemed to be sent to the server properly, now we check to make sure that the database reflects the change
	if ($result !== false)
	{
		$parInfo = PS_getPGAbyUsername($PSdbh, $PGAuser);
		$postCred = $parInfo['CREDENTIAL'];
		$postCredEnc = $parInfo['ENCRYPTIONMODE']; //For PS7 changed from ISCREDENTIALENC TO ENCRYPTIONMODE
		$postModCred = $parInfo['MOD_CRED'];
				
		$result = ($postModCred != $preModCred && $postCredEnc == 1) ? true : false;
		
		//if the credential hash changed we need to update the ps_parent table so it matches on the next check.
		if ($result)
		{
			//update the ps_parent table with the new encrypted password hash
			//echo "\nStoring new password hash for user $PGAuser...";
			$result = update_ps_parent_pcas_creds($AUXdbh, $PGAuser, $postCred);
			//echo ($pcas_res) ? "success." : "failed!";
		}
		
	}
	
}

//return true/false, ONLY means the data was sent...not actually accepted
//For verification this record SHOULD be checked via ODBC somehow, because a simple test is not easily done here
//return ($result == 'success') ? true : false;
return $result;
}


function PS_getPGAProfileByEmail($email)
{
global $PScfg;
/*
 * Queries the PS interface for a PGA with a specific e-mail address
 * Input: E-mail Address (string)
 * Outputs (inherited from PS_scrapePGAprofile): boolean false on no match found, or
 *         an array containing key/value pairs, 'gai', 'firstname', 'lastname', 'email' and 'username')
 */

//set POST variables
$url = $PScfg['guardian_query'];
$cookie = $PScfg['cookie'];

$fields = array(
						'searchParameters.email'=>urlencode($email)
				);

//url-ify the data for the POST
$fields_string = '';
foreach($fields as $key=>$value) { $fields_string .= $key.'='.$value.'&'; }
rtrim($fields_string,'&');

//add some more headers to the default
$headers = array_merge($PScfg['http_headers'],array(
	"Content-Type: application/x-www-form-urlencoded",
	"Content-Length: " . strlen($fields_string),
	)
);

//open connection
$ch = curl_init();

//set the url, number of POST vars, POST data
curl_setopt ($ch, CURLOPT_COOKIEJAR, $cookie); //reuse the same cookiejar from above
curl_setopt ($ch, CURLOPT_COOKIEFILE, $cookie); //send the same cookie data from above
curl_setopt($ch, CURLOPT_HTTPHEADER, $headers); //send along our custom headers from above
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch,CURLOPT_URL,$url);
curl_setopt($ch,CURLOPT_POST,true);
curl_setopt($ch,CURLOPT_POSTFIELDS,$fields_string);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);

//execute post
$result = curl_exec($ch);

//close connection
curl_close($ch);

//search the source code for the important data
return PS_scrapePGAprofile($result);
}


function PS_scrapeSecrets($src)
{
/*
 * Searches PS source code for the PSToken and PSKey
 * Inputs: $src (The remote source code (as a string) just fetched from the PS login page)
 * Outputs: $secrets (An array containing two key/value pairs, 'pskey' and 'pstoken')
 */

//PSKey pattern 
$patternPSKey = '/var pskey = "(?P<pskey>\w+)"/';

//PSToken pattern
$patternPSToken = '/input type="hidden" name="pstoken" value="(?P<pstoken>\w+)"/';

//lookup the pskey in the source code
preg_match($patternPSKey, $src, $matches);
$pskey = $matches['pskey'];

//lookup the pstoken in the source code
preg_match($patternPSToken, $src, $matches);
$pstoken = $matches['pstoken'];

return array('pskey'=>$pskey,'pstoken'=>$pstoken);
}


function PS_scrapePGAprofile($src)
{
/*
 * Searches PS source code for the PGA gai ***This can be done more reliably with ODBC access***
 * Inputs: $src (The remote source code (as a string) just fetched from the PGA profile page)
 * Outputs: boolean false on no match found, or
 *          an array containing key/value pairs, 'gai', 'firstname', 'lastname', 'email' and 'username')
 */

//PGAgai pattern 
$patternPGAgai = '/input type="hidden" id="guardian-edit-form-gai" name="gai" value="(?P<PGAgai>\S+)"/';

//PGAfirst pattern
$patternPGAfirst = '/input type="text" value="(?P<PGAfirst>.+)" name="firstName"/';

//PGAlast pattern
$patternPGAlast = '/input type="text" value="(?P<PGAlast>.+)" name="lastName"/';

//PGAemail pattern
$patternPGAemail = '/input type="text" value="(?P<PGAemail>\S+)" name="email"/';

//PGAusername pattern
$patternPGAusername = '/input type="text" value="(?P<PGAusername>\S+)" name="username"/';

//lookup the PGA GAI in the source code
preg_match($patternPGAgai, $src, $matches);
$PGAgai = $matches['PGAgai'];

//if after this first test we didn't have any results, there is no need to proceed, just return false
if (count($matches) == 0)
{
	return false;
}

//lookup the First Name in the source code
preg_match($patternPGAfirst, $src, $matches);
$PGAfirst = $matches['PGAfirst'];

//lookup the Last Name in the source code
preg_match($patternPGAlast, $src, $matches);
$PGAlast = $matches['PGAlast'];

//lookup the Email in the source code
preg_match($patternPGAemail, $src, $matches);
$PGAemail = $matches['PGAemail'];

//lookup the Username in the source code
preg_match($patternPGAusername, $src, $matches);
$PGAusername = $matches['PGAusername'];

return array('gai'=>$PGAgai, 'firstname'=>$PGAfirst, 'lastname'=>$PGAlast, 'email'=>$PGAemail, 'username'=>$PGAusername);
}


function PS_getPGADetails (&$dbh = false, $type, $val)
{
	global $PScfg;
	
	$pgaAry = false;
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false)
	{
		$whereClause = "WHERE 1=2";
	
		switch ($type)
		{
			case 'all':
				$whereClause = "";
				break;
			
			case 'email':
				$whereClause = "WHERE pe.emailaddress = '$val'";
				break;
			
			case 'actid':
				$whereClause = "WHERE g.accountidentifier = '$val'"	;	
				break;
			
			case 'gid':
				$whereClause = "WHERE g.guardianid = '$val'"	;	
				break;
			
			case 'username':
				$whereClause = "WHERE pa.username = '$val'"	;	
				break;
			
			default:
				//keep the default value from above
				break;
		}
	
		//For PS7, removed pa.iscredentialencrypted added pa.encryptionmode and added mod_pcas and mod_cred
		$query = <<<EOD
SELECT g.accountidentifier accountidentifi, pe.emailaddress email, g.firstname, g.guardianid, g.lastname, pa.credential, pa.encryptionmode, pa.isenabled, pa.pcas_accountid, pa.username, TO_CHAR(pa.whenmodified, 'YYYY-MM-DD HH24:MI:SS') mod_pcas, TO_CHAR(pa.credentialchangeddate, 'YYYY-MM-DD HH24:MI:SS') mod_cred
FROM guardian g
INNER JOIN pcas_account pa ON g.accountidentifier = pa.pcas_accounttoken
INNER JOIN pcas_emailcontact pe ON pa.pcas_accountid = pe.pcas_accountid
$whereClause
ORDER BY g.lastname, g.firstname, g.guardianid
EOD;

		$array = psdb_fetch_array($dbh, $query);
		
		//return a multi-dimensional array if there were any records returned
		if ($array !== false && count($array) > 0) $pgaAry = $array;
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		//remove the "==" sign at the end of the base64 Guardian AccountIdentifier field because PS won't recieve it over GET URL
		$val = ($type == 'actid') ? str_replace('==','',$val) : $val;
		
		$url = $PScfg['pgainfo'] . "?type=" . urlencode($type) . "&val=" . urlencode($val);
		$src = touch_ps_page($url);
		
		$ary = html_table_to_array($src);

		//return a multi-dimensional array if there were any records returned
		if (count($ary) > 0) $pgaAry = $ary;
	}
	
	return $pgaAry;
}


function PS_getPGADetailsAll (&$dbh = false)
{
	//returns a multidimensional array: [0] => array(key1 => val1, key2 => val2), [1] => array(key1 => val1, key2 => val2), [3] => ...etc.
	//returns false on error or no records returned.
	return PS_getPGADetails($dbh, 'all', '');
}


function PS_getPGAbyEmail (&$dbh, $email)
{
	//returns a simple array: (key1 => val1, key2 => val2, ...etc)
	//returns false on error or if other than exactly one record returned.
	
	$ary = PS_getPGADetails ($dbh, 'email', $email);
	
	return ($ary !== false && count($ary) == 1) ? $ary[0] : false;
}


function PS_getPGAbyActID (&$dbh, $actID)
{
	//returns a simple array: (key1 => val1, key2 => val2, ...etc)
	//returns false on error or if other than exactly one record returned.
	
	$ary = PS_getPGADetails ($dbh, 'actid', $actID);
	
	return ($ary !== false && count($ary) == 1) ? $ary[0] : false;
}


function PS_getPGAbyGID (&$dbh, $gID)
{
	//returns a simple array: (key1 => val1, key2 => val2, ...etc)
	//returns false on error or if other than exactly one record returned.
	
	$ary = PS_getPGADetails ($dbh, 'gid', $gID);
	
	return ($ary !== false && count($ary) == 1) ? $ary[0] : false;
}

function PS_getPGAbyUsername (&$dbh, $gID)
{
	//returns a simple array: (key1 => val1, key2 => val2, ...etc)
	//returns false on error or if other than exactly one record returned.
	
	$ary = PS_getPGADetails ($dbh, 'username', $gID);
	
	return ($ary !== false && count($ary) == 1) ? $ary[0] : false;
}


function PS_getPGAKids (&$dbh = false, $gid)
{
	global $PScfg;
	
	$kidAry = false;
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false)
	{
		$query = <<<EOD
SELECT studentsdcid, guardianrelationshiptypeid guardianrelatio
FROM guardianstudent
WHERE guardianid = '$gid'
EOD;

		$array = psdb_fetch_array($dbh, $query);
	
		if ($array !== false && count($array) > 0) 
		{
			$kidAry = array();
		
			foreach ($array as $key => $kid)
			{
				$kidAry[$kid['STUDENTSDCID']] = $kid['GUARDIANRELATIO'];
			}
	
		}
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		$url = $PScfg['pgakids'] . "?gid=" . urlencode($gid);
		$src = touch_ps_page($url);
		
		$ary = html_table_to_array($src);
		
		if (count($ary) > 0)
		{
			foreach ($ary as $key => $kid)
			{
				$kidAry[$kid['STUDENTSDCID']] = $kid['GUARDIANRELATIO'];
			}
		}
	}

	return $kidAry;
}


function PS_getAllPGAKids (&$dbh = false)
{
	global $PScfg;
	
	$kidAry = false;
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false)
	{
		$query = <<<EOD
SELECT guardianid, studentsdcid, guardianrelationshiptypeid guardianrelatio
FROM guardianstudent
ORDER BY guardianid, studentsdcid
EOD;

		$array = psdb_fetch_array($dbh, $query);
	
		if ($array !== false && count($array) > 0) 
		{
			$kidAry = array();
		
			foreach ($array as $key => $kid)
			{
				$kidAry[$kid['GUARDIANID']][$kid['STUDENTSDCID']] = $kid['GUARDIANRELATIO'];
			}
	
		}
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		$url = $PScfg['pgakids'] . "?gid=all";
		$src = touch_ps_page($url);
		
		$ary = html_table_to_array($src);
		
		if (count($ary) > 0)
		{
			foreach ($ary as $key => $kid)
			{
				$kidAry[$kid['GUARDIANID']][$kid['STUDENTSDCID']] = $kid['GUARDIANRELATIO'];
			}
		}
	}

	return $kidAry;
}


function PS_getStuDetails (&$dbh = false, $type, $val)
{
	/*
	$type can be a string of "all" or other options indicated below to determine the WHERE statement
	$val can be a single value or array but is ultimately going to be a list of values that will be used in a SQL IN (val1, val2, ...etc) statement
	*/
	
	global $PScfg;
	
	$stuAry = false;
	$valList = (is_array($val)) ? implode("','", $val) : $val;
	$valList = "'" . $valList . "'";
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false)
	{
		$whereClause = "WHERE 1=2";
	
		switch ($type)
		{
			case 'all':
				$whereClause = "";
				break;
			
			case 'stunum':
				$whereClause = "WHERE s.student_number IN ($valList)";
				break;
				
			case 'dcid':
				$whereClause = "WHERE s.dcid IN ($valList)";
				break;
			
			default:
				//keep the default value from above
				break;
		}
	
		$query = <<<EOD
SELECT s.dcid, s.student_number, s.last_name, s.first_name
FROM students s
$whereClause
ORDER BY s.last_name, s.first_name, s.dcid
EOD;

		$array = psdb_fetch_array($dbh, $query);
		
		//return a multi-dimensional array if there were any records returned
		if ($array !== false && count($array) > 0) $stuAry = $array;
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		$url = $PScfg['stuinfo'] . "?type=" . urlencode($type) . "&val=" . urlencode($valList);
		$src = touch_ps_page($url);
		
		$ary = html_table_to_array($src);
		
		//return a multi-dimensional array if there were any records returned
		if (count($ary) > 0) $stuAry = $ary;
	}
	
	return $stuAry;
}


function PS_getStuDetailsAll (&$dbh = false)
{
	//returns a multidimensional array: [0] => array(key1 => val1, key2 => val2), [1] => array(key1 => val1, key2 => val2), [3] => ...etc.
	//returns false on error or no records returned.
	return PS_getStuDetails($dbh, 'all', '');
}


function PS_getStudentDCIDbyStuNum (&$dbh = false, $IDAry)
{
	/* Takes an array of PowerSchool Student_Number and returns an array of key = Student_Number, value = DCID */
	$IDs = false;

	$array = PS_getStuDetails($dbh, 'stunum', $IDAry);
	
	if (count($array) > 0)
	{
		$IDs = array();
		
		foreach ($array as $key => $kid)
		{
			$IDs[$kid['STUDENT_NUMBER']] = $kid['DCID'];
		}
		
	}

	return $IDs;
}


function PS_getAllStudentDCIDbyStuNum (&$dbh = false)
{
	/* Takes an array of PowerSchool Student_Number and returns an array of key = Student_Number, value = DCID */
	$IDs = false;
	
	$array = PS_getStuDetailsAll($dbh);
	
	if (count($array) > 0)
	{
		$IDs = array();
		
		foreach ($array as $key => $kid)
		{
			$IDs[$kid['STUDENT_NUMBER']] = $kid['DCID'];
		}
		
	}

	return $IDs;
}


function PS_getStuDemoPGDetails (&$dbh = false, $type, $val)
{
	/*
	This function is essentially a duplicate of PS_getStudDetails but since it calls numerous custom fields which are slower (I think) I wanted to separate it out
	Testing is needed...but if performance wouldn't be dramatically effected we could just added the retrieved columns below to the existing PS_getStudDetails function
	$type can be a string of "all" or other options indicated below to determine the WHERE statement
	$val can be a single value or array but is ultimately going to be a list of values that will be used in a SQL IN (val1, val2, ...etc) statement
	*/
	
	global $PScfg;
	
	$stuAry = false;
	$valList = (is_array($val)) ? implode("','", $val) : $val;
	$valList = "'" . $valList . "'";
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false)
	{
		$whereClause = "WHERE 1=2";
	
		switch ($type)
		{
			case 'all':
				$whereClause = "";
				break;
			
			case 'stunum':
				$whereClause = "WHERE s.student_number IN ($valList)";
				break;
				
			case 'dcid':
				$whereClause = "WHERE s.dcid IN ($valList)";
				break;
			
			default:
				//keep the default value from above
				break;
		}
	
		$query = <<<EOD
SELECT
s.dcid, s.student_number, s.last_name, s.first_name,
ps_customfields.getcf ('students', id, 'zz_PG1_email') pg1_email,
ps_customfields.getcf ('students', id, 'zz_PG2_email') pg2_email,
ps_customfields.getcf ('students', id, 'zz_PG3_email') pg3_email,
ps_customfields.getcf ('students', id, 'zz_PG4_email') pg4_email
FROM students s
$whereClause
ORDER BY s.last_name, s.first_name, s.dcid
EOD;

		$array = psdb_fetch_array($dbh, $query);
		
		//return a multi-dimensional array if there were any records returned
		if ($array !== false && count($array) > 0) $stuAry = $array;
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		$url = $PScfg['stuparinfo'] . "?type=" . urlencode($type) . "&val=" . urlencode($valList);
		$src = touch_ps_page($url);
		
		$ary = html_table_to_array($src);
		
		//return a multi-dimensional array if there were any records returned
		if (count($ary) > 0) $stuAry = $ary;
	}
	
	return $stuAry;
}


function PS_getPGEmailsbyDCID (&$dbh, $dcid)
{
	//returns a simple array: (PG1 => EmailForPG1, PG2 => EmailForPG2, ...etc)
	//returns false on error or if other than exactly one record returned.
	
	$emailAry = false;
	
	$ary = PS_getStuDemoPGDetails ($dbh, 'dcid', $dcid);
	
	if ($ary !== false && count($ary) == 1)
	{
		$a = $ary[0]; //array was multidimensional
		$emailAry = array('PG1' => $a['PG1_EMAIL'], 'PG2' => $a['PG2_EMAIL'], 'PG3' => $a['PG3_EMAIL'], 'PG4' => $a['PG4_EMAIL']);
	}
	
	return $emailAry;
}


function PS_getCourseList (&$dbh = false, $type, $val)
{
	/*
	$type can be a string of "all" or other options indicated below to determine the WHERE statement
	$val can be a single value or array but is ultimately going to be a list of values that will be used in a SQL IN (val1, val2, ...etc) statement
	*/
	
	global $PScfg;
	
	$courseAry = false;
	$valList = (is_array($val)) ? implode("','", $val) : $val;
	$valList = "'" . $valList . "'";
	
	//test that we have a database connection and should therefore use SQL to retrieve this information
	if($dbh !== false AND 1==2) //Temporarily disabled until ODBC is back online and this can be tested
	{
		$whereClause = "WHERE 1=2";
	
		switch ($type)
		{
			case 'all':
				$whereClause = "";
				break;
			
			case 'stunum':
				$whereClause = "WHERE s.student_number IN ($valList)";
				break;
				
			case 'dcid':
				$whereClause = "WHERE s.dcid IN ($valList)";
				break;
			
			default:
				//keep the default value from above
				break;
		}
	
		$query = <<<EOD
SELECT s.dcid, s.student_number, s.last_name, s.first_name
FROM students s
$whereClause
ORDER BY s.last_name, s.first_name, s.dcid
EOD;

		$array = psdb_fetch_array($dbh, $query);
		
		//return a multi-dimensional array if there were any records returned
		if ($array !== false && count($array) > 0) $stuAry = $array;
	}
	//else we have a false database connection and should attempt to use screen scraping techniques to retrieve this information
	else
	{
		$url = $PScfg['stucourseinfo'] . "?type=" . urlencode($type) . "&val=" . urlencode($valList);
		$src = touch_ps_page($url);
	
		$ary = html_table_to_array($src);

		//return a multi-dimensional array if there were any records returned
		if (count($ary) > 0) $courseAry = $ary;
	}
	
	return $courseAry;
}


/* http://www.php.net/manual/en/function.curl-setopt.php#100716 */
function _curl_parse_cookiefile($file) {
    $aCookies = array();
    $aLines = file($file);
    foreach($aLines as $line){
      if('#'==$line{0})
        continue;
      $arr = explode("\t", $line);
      if(isset($arr[5]) && isset($arr[6]))
        $aCookies[$arr[5]] = $arr[6];
    }
   
    return $aCookies;
}
  
/*
* Convert HTML source code with an HTML table into a PHP array
* Code from: http://blog.mspace.fm/2009/10/14/parse-an-html-table-with-php/
*/
function html_table_to_array($html)
{
  // Find the table
  preg_match("/<table.*?>.*?<\/[\s]*table>/s", $html, $table_html);
 
  // Get title for each row
  preg_match_all("/<th.*?>(.*?)<\/[\s]*th>/", $table_html[0], $matches);
  $row_headers = $matches[1];

  // Iterate each row
  preg_match_all("/<tr.*?>(.*?)<\/[\s]*tr>/s", $table_html[0], $matches);
 
  $table = array();
 
  foreach($matches[1] as $row_html)
  {
    preg_match_all("/<td.*?>(.*?)<\/[\s]*td>/", $row_html, $td_matches);
    $row = array();
    for($i=0; $i<count($td_matches[1]); $i++)
    {
      $td = strip_tags(html_entity_decode($td_matches[1][$i]));
      $row[$row_headers[$i]] = $td;
    }
 
    if(count($row) > 0)
      $table[] = $row;
  }
  return $table;
}  
?>

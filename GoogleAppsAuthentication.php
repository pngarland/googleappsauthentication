<?php
 
$wgExtensionCredits['other'][] = array(
        'name' => 'Google Apps Authentication',
        'version' => '1.0',
        'path' => __FILE__,
        'author' => array( 'Emanuele Nanetti', 'Bertrand Gorge' ),
        'url' => 'http://www.mediawiki.org/wiki/Extension:GoogleAppsAuthentification',
);
 
if (empty($wgDefaultUserOptions['GoogleAppsDomain']))
        die('Please set up the google app domain first : $wgDefaultUserOptions[\'GoogleAppsDomain\'] = "yourdomain.com"');
 
// The domain name should be set up before the include in LocalSettings.php:
// $wgDefaultUserOptions['GoogleAppsDomain'] = 'yourdomain.com';
 
 
// Now for the code:
 
$wgHooks['UserLoadFromSession'][] = 'fnGoogleAppsAuthenticateHook';
 
$path = dirname( __FILE__ );
set_include_path( implode( PATH_SEPARATOR, array( $path ) ) . PATH_SEPARATOR . get_include_path() );
 
define('Auth_Yadis_CURL_OVERRIDE', true);
 
/**
 * An extension can use this hook to fill in the data of the User object
 * $user from an external session. This is typically used in Authentication extensions.
 *
 * When the authentication should continue undisturbed after the hook was executed,
 * do not touch $result. When the normal authentication should not happen (e.g.,
 * because $user is completely initialized), set $result to any boolean value.
 *
 * In any case, return true.
 *
 * See the talk page for sample code for this hook.
 *
 * @param $user user object being loaded
 * @param $result set this to a boolean value to abort the normal authentication process
 */
function fnGoogleAppsAuthenticateHook($user, &$result)
{
        global $IP, $wgLanguageCode, $wgRequest, $wgOut;
 
        if (isset($_REQUEST["title"]))
        {
                $lg = Language::factory($wgLanguageCode);
 
                if ($_REQUEST["title"] == $lg->specialPage("Userlogin"))
                {
                        // Setup for a web request
                        require_once("$IP/includes/WebStart.php");
 
                        // Here we do our stuff
                        $googleAccount = getGoogleAccount('title=' . $_REQUEST["title"]);
 
                        // Get username
                        $username = $googleAccount['email'];
 
                        // Get MediaWiki user
                        $u = User::newFromName($username);
 
                        // Create a new account if the user does not exists
                        if ($u->getID() == 0)
                        {
                                // Create the user
                                $u->addToDatabase();
                                $u->setRealName($googleAccount['realname']);
                                $u->setEmail($googleAccount['email']);
                                $u->setPassword( md5($username) ); // do something random
                                $u->setToken();
                                $u->saveSettings();
 
                                // Update user count
                                $ssUpdate = new SiteStatsUpdate(0,0,0,0,1);
                                $ssUpdate->doUpdate();
                        }
 
                        $u->setOption("rememberpassword", 1);
                        $u->setCookies();
 
                        $user = $u;
 
                        // Redirect if a returnto parameter exists
                        $returnto = $wgRequest->getVal("returnto");
                        if ($returnto) 
                        {
                                $target = Title::newFromText($returnto);
                                if ($target) 
                                {
                                        // Make sure we don't try to redirect to logout !
                                        if ($target->getNamespace() == NS_SPECIAL)
                                                $url = Title::newMainPage()->getFullUrl();
                                        else
                                                $url = $target->getFullUrl();
 
                                        $wgOut->redirect($url."?action=purge"); //action=purge is used to purge the cache
                                }
                        }
                }
                else if ($_REQUEST["title"] == $lg->specialPage("Userlogout")) 
                {
                        // Logout
                        $user->logout();
                }
        }
 
        // Back to MediaWiki home after login
        return true;
}
 
 
/**
 * returns an array with email, realname
 */
function getGoogleAccount($loginPage)
{
        global $wgDefaultUserOptions;
 
        if (isset($_SESSION['GoogleAppsLoggedInUser']))
                return $_SESSION['GoogleAppsLoggedInUser'];
 
        // Include files
        require_once "Auth/OpenID/Consumer.php";
        require_once "Auth/OpenID/AX.php";
        require_once "Auth/OpenID/google_discovery.php";
        require_once "Auth/OpenID/FileStore.php";
        require_once "Auth/OpenID/SReg.php";
        require_once "Auth/OpenID/PAPE.php";
 
        // Init login
        $tmp = dirname(realpath(__FILE__)).DIRECTORY_SEPARATOR."tmp";
 
        if (!file_exists($tmp))
                die('Temp path '.$tmp.' does not exists');
 
        if (!is_writable($tmp))
                die('Temp path '.$tmp.' is not writable');
 
        $config['tmp_path'] = $tmp;
 
        // Return URL
        $config['return_server'] = (isset($_SERVER["HTTPS"]) ? 'https://' : 'http://') .$_SERVER['SERVER_NAME'].":".$_SERVER['SERVER_PORT'];
        $config['return_url'] = $config['return_server'].$_SERVER['REQUEST_URI'];
 
        // Cache for google discovery (much faster)
        $config['cache'] = new FileCache($config['tmp_path']);
 
        // Open id lib has many warnig and notices
        error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING ^ E_USER_NOTICE);
 
        if (!empty($_GET['janrain_nonce']))     // Google returns with this value after authentication
        {
                $store = new Auth_OpenID_FileStore($config['tmp_path']);
                $consumer = new Auth_OpenID_Consumer($store);
                new GApps_OpenID_Discovery($consumer, null, $config['cache']);
 
                $response = $consumer->complete($config['return_url']);
 
                // Check the response status.
                if ($response->status == Auth_OpenID_CANCEL)
                        die('Verification cancelled.');
 
                if ($response->status == Auth_OpenID_FAILURE)
                        die("OpenID authentication failed: " . $response->message);
 
                if ($response->status != Auth_OpenID_SUCCESS)
                        die('Other error');
 
                // Successful login
 
                // Extract returned information
                $openid = $response->getDisplayIdentifier();
                $ax = new Auth_OpenID_AX_FetchResponse();
                if ($ax)
                        $ax = $ax->fromSuccessResponse($response);
 
                $sreg = Auth_OpenID_SRegResponse::fromSuccessResponse($response);
 
                if ($sreg)
                        $sreg = $sreg->contents();
 
                $_SESSION['GoogleAppsLoggedInUser'] = array(
                                'email' => $_GET['openid_ext1_value_email'],
                                'realname' => ucfirst($_GET['openid_ext1_value_firstname']) . ' ' . ucfirst($_GET['openid_ext1_value_lastname']));
 
                return $_SESSION['GoogleAppsLoggedInUser'];
        }
 
        // No authentification info, so we redirect to Google:
        $store = new Auth_OpenID_FileStore($config['tmp_path']);
        $consumer = new Auth_OpenID_Consumer($store);
        new GApps_OpenID_Discovery($consumer, null, $config['cache']);
 
        try
        {
                $auth_request = $consumer->begin($wgDefaultUserOptions['GoogleAppsDomain']);
                if (!is_object($auth_request))
                        die('Auth request object error. Try again');
        }
        catch (Exception $error)
        {
                die($error->getMessage());
        }
 
        /// Request additional parameters
        $ax = new Auth_OpenID_AX_FetchRequest;
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/email',2,1,'email') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/first',1,1, 'firstname') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/last',1,1, 'lastname') );
 
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson/friendly',1,1,'friendly') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/namePerson',1,1,'fullname') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/birthDate',1,1,'dob') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/person/gender',1,1,'gender') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/postalCode/home',1,1,'postcode') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/contact/country/home',1,1,'country') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/pref/language',1,1,'language') );
        $ax->add( Auth_OpenID_AX_AttrInfo::make('http://axschema.org/pref/timezone',1,1,'timezone') );
 
        $auth_request->addExtension($ax);
 
        // Request URL for auth dialog url
        $redirect_url = $auth_request->redirectURL($config['return_server'], $config['return_url']);
 
        if (Auth_OpenID::isFailure($redirect_url))
                die('Could not redirect to server: ' . $redirect_url->message);
        else
                header('Location: '.$redirect_url);
 
        exit();
}       // end function
 
 
class FileCache {
        var $cache_file;
 
        function __construct($tmp_path) {
                $this->cache_file = $tmp_path.DIRECTORY_SEPARATOR."google.tmp";
        }
 
        function get($name) {
                $cache = unserialize(file_get_contents($this->cache_file));
                return $cache[$name];
        }
 
        function set($name, $value) {
                $cache = unserialize(file_get_contents($this->cache_file));
                $cache[$name] = $value;
                file_put_contents($this->cache_file, serialize($cache));
        }
 
}
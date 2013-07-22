This is a MediaWiki extension that adds Google Apps authentication, and includes all necessary code.  Many thanks to: Bertrand Gorge for creating the plugin, and Constantin Bosneaga for creating the PHP OpenID library.  See below links for more info - 

http://www.mediawiki.org/wiki/Extension:GoogleAppsAuthentification
http://a32.me/2011/03/google-apps-as-single-authentication-point-for-your-corporate-applications/

Instructions:

1. Copy all files in this directory into <media wiki root directory>/extensions/GoogleAppsAuthentication

2. Add the below code to the bottom of LocalSettings.php in root MediaWiki installation directory, filling in the name of your domain:

# ============ Google Apps Authentication ===========

# Make sure nobody can see/edit anything if not logged in:
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['*']['read'] = false;
 
# Make sure everybody can see/edit everything if logged in:
$wgGroupPermissions['user']['read'] = true;
$wgGroupPermissions['user']['edit'] = true;
 
# Tell the extension who should log in (change yourdomain.com):
$wgDefaultUserOptions['GoogleAppsDomain'] = 'addyourdomainhere.com';
 
require_once("$IP/extensions/GoogleAppsAuthentication/GoogleAppsAuthentication.php");

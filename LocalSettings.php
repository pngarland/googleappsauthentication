<?php

# Add the below code to the bottom of LocalSettings.php in root MediaWiki installation directory:

# ============================================= Google Apps Authentication =============================================

# Make sure nobody can see/edit anything if not logged in:
$wgGroupPermissions['*']['edit'] = false;
$wgGroupPermissions['*']['read'] = false;
 
# Make sure everybody can see/edit everything if logged in:
$wgGroupPermissions['user']['read'] = true;
$wgGroupPermissions['user']['edit'] = true;
 
# Tell the extension who should log in (change yourdomain.com):
$wgDefaultUserOptions['GoogleAppsDomain'] = 'healthentic.com';
 
require_once("$IP/extensions/GoogleAppsAuthentication/GoogleAppsAuthentication.php");
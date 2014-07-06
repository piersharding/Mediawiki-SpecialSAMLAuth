<?php

/*
 * SAMLAuth Extension for MediaWiki
 *
 * Copyright (C) 2009, Piers Harding, Catalyst IT Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 * http://www.gnu.org/copyleft/gpl.html
 */

# Alert the user that this is not a valid entry point to MediaWiki if they try to access the special pages file directly.
if (!defined('MEDIAWIKI')) {
        echo <<<EOT
To install the SAML Auth extension, put the following line in LocalSettings.php:
require_once( "\$IP/extensions/SpecialSAMLAuth/SpecialSAMLAuth.php" );
EOT;
        exit( 1 );
}
 
$wgExtensionCredits['specialpage'][] = array(
    'name' => 'SAMLAuth',
    'author' => 'Piers Harding',
    'url' => 'http://www.mediawiki.org/wiki/Extension:SAMLAuth',
    'description' => 'This extension provides a Special:SAMLAuth page that enables SAML based authentication',
    'descriptionmsg' => 'samlauth-desc',
    'version' => '0.0.3',
);
 
$dir = dirname(__FILE__) . '/';
 
$wgAutoloadClasses['SAMLAuthHooks'] = $dir . 'SAMLAuth.hooks.php';
$wgAutoloadClasses['SAMLAuth'] = $dir . 'SpecialSAMLAuth_body.php'; # Tell MediaWiki to load the extension body.
$wgExtensionMessagesFiles['SAMLAuth'] = $dir . 'SpecialSAMLAuth.i18n.php';
$wgExtensionAliasesFiles['SAMLAuth'] = $dir . 'SpecialSAMLAuth.alias.php';
$wgSpecialPages['SAMLAuth'] = 'SAMLAuth'; # Let MediaWiki know about your new special page
$wgHooks["UserLogoutComplete"][] = "SAMLAuthHooks::logout";
$wgHooks['MediaWikiPerformAction'][] = 'SAMLAuthHooks::checkSAMLLogin';


// Configuration of SAMLAuth extension
global $wgSAMLAuthSimpleSAMLphpLibPath, $wgSAMLAuthSimpleSAMLphpConfigPath, $wgSAMLAuthSimpleSAMLphpentity, $wgSAMLAuthUserNameAttr, $wgSAMLAuthRealNameAttr, $wgSAMLAuthEmailAttr, $wgSamlAuthDebug, $wgSAMLVerifyIdP, $wgSAMLCreateUser;
//$wgSAMLAuthSimpleSAMLphpLibPath = '/usr/local/mw-test/simplesamlphp-1.5';  // Library path for SimpleSAMLphp
$wgSAMLAuthSimpleSAMLphpLibPath = '/home/piers/git/public/simplesamlphp';  // Library path for SimpleSAMLphp
//$wgSAMLAuthSimpleSAMLphpConfigPath = '/usr/local/mw-test/simplesamlphp-1.5/config';  // config.php path for SimpleSAMLphp
$wgSAMLAuthSimpleSAMLphpConfigPath = '/home/piers/git/public/simplesamlphp/config';  // config.php path for SimpleSAMLphp
$wgSAMLAuthSimpleSAMLphpentity = 'default-sp'; // The SimpeSAMLphp SP authentication entity
$wgSAMLAuthUserNameAttr = 'eduPersonPrincipalName';     // User name attribute
$wgSAMLAuthRealNameAttr = 'cn';      // Real Name attribute
$wgSAMLAuthEmailAttr    = 'mail';    // email address attribute

// verify if user's IdP is known in the user settings?
$wgSAMLVerifyIdP = false;

// create user accounts for users that do not exist?
$wgSAMLCreateUser = false;

// auto logout from IdP?
global $wgSAMLAuthAutoLogout;
$wgSAMLAuthAutoLogout = true;

// activate debugging messages that go to apache error log
$wgSamlAuthDebug = false;

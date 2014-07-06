<?php

/*
 * SAMLAuth Extension for MediaWiki
 *
 * Copyright (C) 2010, Piers Harding, Catalyst IT Ltd
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

class SAMLAuth extends SpecialPage {
    
    function __construct() {
        parent::__construct( 'SAMLAuth' );
        wfLoadExtensionMessages('SAMLAuth');
    }

    /*
     * basic form execution step - all of the SAML authenticaiton dance happens 
     * here
     */ 
    function execute( $par ) {
        global $wgRequest, $wgOut, $wgUser, $IP, $wgAuth, $wgContLang, $wgSessionName, $wgSessionName, $wgCookiePrefix;
        global $wgSAMLAuthSimpleSAMLphpLibPath, $wgSAMLAuthSimpleSAMLphpConfigPath, $wgSAMLAuthSimpleSAMLphpentity, $wgSAMLAuthUserNameAttr, $wgSAMLAuthRealNameAttr, $wgSAMLAuthEmailAttr;
        global $wgSAMLCreateUser, $wgSAMLVerifyIdP;
        global $simplesaml_RN, $simplesaml_email;
        global $wgSamlAuthDebug;
        
        // save all the session settings to recreate later - after SimpleSAMLphp
        // has been messing with it
        $tmp_path = ini_get('session.save_path');
        $tmp_session = session_name();
        $tmp_cookie_params = session_get_cookie_params();
        $tmp_session_id = session_id();
        
        // Point to the include file of your simpleSAMLphp installation.
        require_once($wgSAMLAuthSimpleSAMLphpLibPath . '/lib/_autoload.php');
        SimpleSAML_Configuration::init($wgSAMLAuthSimpleSAMLphpConfigPath);
        // get all the SAML information
        $as = new SimpleSAML_Auth_Simple($wgSAMLAuthSimpleSAMLphpentity);
        $saml_config = SimpleSAML_Configuration::getInstance();
        $saml_session = SimpleSAML_Session::getInstance();
        $valid_saml_session = $saml_session->isValid($wgSAMLAuthSimpleSAMLphpentity);
        
        // close the saml session, and discard for now
        session_write_close();
        session_unset();
        unset($_SESSION['SimpleSAML_Session']);
        unset($USER);        
        
        if (!$valid_saml_session) { # 
            // not valid session. Ship user off to Identity Provider
            $as->requireAuth();
        } 
        else {
            // Valid session. Register or update user in Moodle, log him on, and redirect to Moodle front
            $attributes = $as->getAttributes();
            $session = SimpleSAML_Session::getInstance();
            $idp = $session->getIdP();
	    $wgSamlAuthDebug && error_log('IDP: ' . $idp);
	    $wgSamlAuthDebug && error_log('attributes: ' . var_export($attributes, true));
            $simplesaml_RN = $attributes[$wgSAMLAuthRealNameAttr][0];
            $simplesaml_email = $attributes[$wgSAMLAuthEmailAttr][0];

            // convert all to lower case
            $simplesaml_UN = $wgContLang->lc($attributes[$wgSAMLAuthUserNameAttr][0]);
            if ($wgSAMLVerifyIdP && false == filter_var($simplesaml_UN, FILTER_VALIDATE_EMAIL)) {
                // fail the login as this is not a fully qualified user name + organisation
                $wgSamlAuthDebug && error_log('Debug simpleSAMLphp + MediaWiki: USER-LOGIN [' . $simplesaml_RN . ',' . $simplesaml_email . ',' . $simplesaml_UN . '] - login name not fully qualified - login failed, going for fall back');
                $target = Title::newFromText('Main_Page');
                $wgOut->redirect($target->getFullUrl()."?action=purge"); //action=purge is used to purge the cache
                return;
            }

            // convert name to a sanitized format - strip out unwanted characters
            $simplesaml_UN = preg_replace('/[\(\?\,\ \&\/\<\>\[\]\'\"\\\|\{\}\!\#\$\%\^\*\(\)\+\=]/', '', $simplesaml_UN);
            $name_parts = array();
            foreach (preg_split('/[\.\_\-\@]/', $simplesaml_UN) as $part) {
                $name_parts []= $wgContLang->ucfirst($part);
            }
            // uppercase the first char
            $simplesaml_UN = $wgContLang->ucfirst(implode(' ', $name_parts));
         
            // Check the apache error log to see that the correct user attributes are reckognized.
            $wgSamlAuthDebug && error_log('Debug simpleSAMLphp + MediaWiki: USER-LOGIN [' . $simplesaml_RN . ',' . $simplesaml_email . ',' . $simplesaml_UN . ']');

            // reset all the session values the way they were, and start the session
            ini_set('session.save_path', $tmp_path);
            session_name($tmp_session);
            session_set_cookie_params($tmp_cookie_params['lifetime'], $tmp_cookie_params['path'], $tmp_cookie_params['domain'], $tmp_cookie_params['secure'], $tmp_cookie_params['httponly']);
            session_start();
            $tmp_session_id = session_id();
            setcookie($tmp_session, $tmp_session_id, 0, $tmp_cookie_params['path'], $tmp_cookie_params['domain'], $tmp_cookie_params['secure'], $tmp_cookie_params['httponly']);

            require_once($IP.'/includes/specials/SpecialUserlogin.php');
            if (User::idFromName($simplesaml_UN) != null) {
                // Submit a fake login form to authenticate the user.
                $user = User::newFromName($simplesaml_UN);
                $user->load();
                LoginForm::setLoginToken();
                $token = LoginForm::getLoginToken();
                $params = new FauxRequest(array(
                    'wpName' => $simplesaml_UN,
                    'wpPassword' => 'a',
                    'wpDomain' => '',
                    'wpRemember' => '',
                    'wpLoginToken' => $token,
                    ));
                 
                // construct the dummy authentication plugin - this will
                // authenticate, and update user info
                $wgAuth = new SAMLAuthLogin();
                $loginForm = new LoginForm($params);
                $result = $loginForm->authenticateUserData();
                if ($result != LoginForm::SUCCESS) {
                    error_log('Unexpected REMOTE_USER authentication failure. ' . $result);
                    $target = Title::newFromText('Main_Page');
                    $wgOut->redirect($target->getFullUrl()."?action=purge"); //action=purge is used to purge the cache
                    return;
                }
                
                if ($wgSAMLVerifyIdP && $idp != $wgUser->getOption('SAMLAuth_IdentityProvider')) {
                    error_log('simpleSAMLphp IdP on user not same as current selection: ' . $idp . ' - ' . $wgUser->getOption('SAMLAuth_IdentityProvider'));
                    $target = Title::newFromText('Main_Page');
                    $wgOut->redirect($target->getFullUrl()."?action=purge"); //action=purge is used to purge the cache
                    return;
                }
                $wgSamlAuthDebug && error_log('IDP on user: '.$wgUser->getOption('SAMLAuth_IdentityProvider'));
                // Update the user values, on each login
                $user->setOption('SAMLAuth_IdentityProvider', $idp);
                if($simplesaml_email != null) {
                    $user->setEmail($simplesaml_email);
                }
                if($simplesaml_RN != null) {
                    $user->setRealName($simplesaml_RN);
                }
                $wgUser->saveSettings();
                wfSetupSession();
                $wgSamlAuthDebug && error_log('Debug simpleSAMLphp + MediaWiki: USER-IDENTIFIED [' . $simplesaml_UN . ']');
                $wgUser->setCookies();
            } 
            else if ($wgSAMLCreateUser) {
                // user does not exist - lets create them
                $user = User::newFromSession();
                 
                // Submit a fake login form to authenticate the user.
                $user = User::newFromName($simplesaml_UN);
                $user->setName($simplesaml_UN);
                $user->load();
                $user->setToken();
                $token = $user->getToken();
                $params = new FauxRequest(array(
                    'wpName' => $simplesaml_UN,
                    'wpPassword' => '',
                    'wpDomain' => '',
                    'wpRemember' => '',
                    'wpLoginToken' => $token,
                    ));
                 
                // construct the dummy authentication plugin - this will
                // authenticate, and update user info
                $wgAuth = new SAMLAuthLogin();
                $loginForm = new LoginForm($params);
                $result = $loginForm->authenticateUserData();

                /* For security, scramble the password to ensure the user can
                 * only login through simpleSAMLphp.  This set the password to a 15 byte
                 * random string.
                 */
                $pass = null;
                for($i = 0; $i < 15; ++$i)
                        $pass .= chr(mt_rand(0,255));
                $loginForm->mPassword = $pass;

                //Now we _do_ the black magic
                $loginForm->mRemember = false;
                $loginForm->initUser($user, TRUE);

                // set the user values
                $user->setOption('SAMLAuth_IdentityProvider', $idp);
                if($simplesaml_email != null) {
                    $user->setEmail($simplesaml_email);
                }
                if($simplesaml_RN != null) {
                    $user->setRealName($simplesaml_RN);
                }

                // email confirmation loop
                global $wgEmailAuthentication;
                if( $wgEmailAuthentication && User::isValidEmailAddr( $user->getEmail() ) ) {
                    $user->sendConfirmationMail();
                }
        
                //Finish it off
                $user->setToken();
                $user->saveSettings();
                wfSetupSession();
                $user->setCookies();
                $wgUser = $user;
                $user->addNewUserLogEntry();
                wfRunHooks( 'AddNewAccount', array( $user ) );
            } else {
                $wgSamlAuthDebug &&  error_log('SpecialSamlAuth: User does not exist and we may not create an account');
                $target = Title::newFromText('Main_Page');
                $wgOut->redirect($target->getFullUrl()."?action=purge"); //action=purge is used to purge the cache
            }
                
            // mark this session as SAML Controlled
            $_SESSION['SAMLSessionControlled'] = true;
              
            // Get returnto value
            $returnto = $wgRequest->getVal("returnto");
            if ($returnto) {
                $target = Title::newFromText($returnto);
            }
            if (empty($target)) {
                $target = Title::newFromText('Main_Page');
            }
            $wgOut->redirect($target->getFullUrl()."?action=purge"); //action=purge is used to purge the cache
        }
        
    }

}

// simple auth plugin to simulate login 
class SAMLAuthLogin extends AuthPlugin {
    
    // automatically authenticate the user
    function authenticate($username, $password) {
        return true;
    }
    
    function autoCreate() {
            return false;
    }

    function allowPasswordChange() {
        return true;
    }

    function canCreateAccounts() {
            return false;
    }

    function addUser( $user, $password ) {
            return false;
    }

    function strict() {
            return false;
    }
    
    /**
     * When a user logs in, optionally fill in preferences and such.
     * For instance, you might pull the email address or real name from the
     * external user database.
     *
     * The User object is passed by reference so it can be modified; don't
     * forget the & on your function declaration.
     *
     * @param User $user
     * @access public
     */
    function updateUser( &$user ) {
        global $simplesaml_email;
        global $simplesaml_RN;
                                                                
        if($simplesaml_email != null)
                $user->setEmail($simplesaml_email);
        if($simplesaml_RN != null)
                $user->setRealName($simplesaml_RN);
                
        //$user->setPassword('somepassword');
        return true;
    }
    
}


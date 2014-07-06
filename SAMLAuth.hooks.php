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

class SAMLAuthHooks {

    /**
     * On logout - kill the IdP session too, if desired
     */
    static function logout() {
        global $wgSAMLAuthSimpleSAMLphpLibPath, $wgSAMLAuthSimpleSAMLphpConfigPath, $wgSAMLAuthSimpleSAMLphpentity, $wgSAMLAuthAutoLogout;
        global $wgUser, $wgRequest;
     
        // clear out SAML session reference
        unset($_SESSION['SAMLSessionControlled']);
           
        // Logout from MediaWiki
        $wgUser->doLogout();
     
        // Get returnto value
        $redirecturl = '/';
        $returnto = $wgRequest->getVal("returnto");
        if ($returnto) {
            $target = Title::newFromText($returnto);
            if ($target) {
                $redirecturl = $target->getFullUrl()."?action=purge";
            }
        }

        // Point to the include file of your simpleSAMLphp installation.
        require_once($wgSAMLAuthSimpleSAMLphpLibPath . '/lib/_autoload.php');
        SimpleSAML_Configuration::init($wgSAMLAuthSimpleSAMLphpConfigPath);
        
        // do the IdP logout if required
        if ($wgSAMLAuthAutoLogout) {
            // get all the SAML information
            $saml_config = SimpleSAML_Configuration::getInstance();
            $saml_session = SimpleSAML_Session::getInstance();
            $valid_saml_session = $saml_session->isValid($wgSAMLAuthSimpleSAMLphpentity);
            $as = new SimpleSAML_Auth_Simple($wgSAMLAuthSimpleSAMLphpentity);
            
            if($valid_saml_session) {
                $as->logout($redirecturl);
            } else {
                SimpleSAML_Utilities::redirect($redirecturl);
            }
        }
        else {
            SimpleSAML_Utilities::redirect($redirecturl);
        }
        
        // should never ever get here     
        return true;
    }
    
/**
 * Hook run on every page to check if user has valid SAML based login 
 * log user out if they don't
 * @param $output
 * @param $article
 * @param $title
 * @param $user
 * @param $request
 * @param $wiki
 * @return unknown_type
 */    
    static function checkSAMLLogin( $output, $article, $title, $user, $request, $wiki ) {
        global $wgSAMLAuthSimpleSAMLphpLibPath, $wgSAMLAuthSimpleSAMLphpConfigPath, $wgSAMLAuthSimpleSAMLphpentity, $wgSAMLAuthAutoLogout;
        
        if ($user->isLoggedIn()) {
            if (isset($_SESSION['SAMLSessionControlled'])) {
                // Point to the include file of your simpleSAMLphp installation.
                require_once($wgSAMLAuthSimpleSAMLphpLibPath . '/lib/_autoload.php');
                SimpleSAML_Configuration::init($wgSAMLAuthSimpleSAMLphpConfigPath);
                $saml_session = SimpleSAML_Session::getInstance();
                $valid_saml_session = $saml_session->isValid($wgSAMLAuthSimpleSAMLphpentity);
                
                if (!$valid_saml_session) {
                    error_log("in checkSAMLLogin: got an INVALID session - logging user out\n");
                    $wgSAMLAuthAutoLogout = true;
                    SAMLAuthHooks::logout();
                }
            }
        }
        return true;
    }
    
	
}

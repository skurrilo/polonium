<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

namespace polonium\extensions\adapter\security\auth;

use polonium\action\Request;
use polonium\models\Tokens;

class Api extends \lithium\core\Object {
	/**
	 * Called by the `Auth` class to run an authentication check against the Facebook API
	 * and returns an array of user information on success, or `false` on failure.
	 *
	 * @param Request $request the current request object.
	 * @param array $options additional options to be passed into method
	 * @return array Returns an array containing user information on success, or `false` on failure
	 */
	public function check($request, array $options = array()) {
		// get access token from query-param or via http basic-auth username
		$request_token = $request->get('env:php_auth_user');
		if($request_token === null) {
			$request_token = $request->get('query:access_token');
			if($request_token === null) {
				return false;
			}
		}
		$conditions = array(
			'access_token' => $request_token,
			'status' => 'active',
		);
		$fields = array(
			'_id',
		);

		$token = Tokens::find('first', compact('conditions', 'fields'));
		if($token) {
			return $request_token;
		}
		return false;
	}

	/**
	 * A pass-through method called by `Auth`. Returns the value of `$data`, which is written to
	 * a user's session. When implementing a custom adapter, this method may be used to modify or
	 * reject data before it is written to the session.
	 *
	 * @param array $data User data to be written to the session
	 * @param array $options Adapter-specific options. Not implemented in the `Facebook` adapter
	 * @return array Returns the value of `$data`
	 */
	public function set($data, array $options = array()) {
		return $data;
	}

	/**
	 * Called by `Auth` when a user session is terminated. Not implemented in the `Facebook` adapter
	 *
	 * @param array $options Adapter-specific options. Not implemented in the `Facebook` adapter
	 * @return void
	 */
	public function clear(array $options = array()) {
	}

}
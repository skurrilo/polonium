<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

namespace polonium\action;

class Api {

	/**
	 * encode the answer of the media object for API. checks for envelope or callback-query parameter
	 *
	 * @param array $data to encode for returning
	 * @param array $handler of data from media handler
	 * @param Response $response lithium response object
	 * @return string
	 */
	public static function mediaEncode($data, $handler, $response) {
		global $request;
		// check, if we have a request object in $handler or in global var $request
		if(!isset($handler['request']) && !empty($request)) {
			$handler['request'] = $request;
			$callback = $handler['request']->get('query:callback');
			// remove all non letter/digits
			$callback = preg_replace('/[^a-zA-Z0-9_]/','_', $callback);
			$envelope = (boolean) $handler['request']->get('query:envelope');
			$fields = $handler['request']->get('query:fields');
		}
		else {
			$callback = "";
			$envelope = false;
			$fields = false;
		}

		if($fields != false) {
			$response_fields = explode(',',$fields);
			$response_data = array();
			foreach($data as $data_key => $data_value) {
				if(in_array($data_key, $response_fields)) {
					$response_data[$data_key] = $data_value;
				}
			}
			$data = $response_data;
		}

		if($envelope or $callback != false) {
			$data = array('status_code' => $response->status['code'], 'response' => $data);
			if($response->status['code'] != 200) {
				$response->status('code', 200);
			}
		}

		// backward compatibility for PHP 5.3
		if(!defined('JSON_PRETTY_PRINT')) {
			define ('JSON_PRETTY_PRINT', 128);
		}
		$return = json_encode($data, JSON_PRETTY_PRINT);

		if($callback != false) {
			$return = $callback.'('.$return.');';
		}
		return $return;
	}
}
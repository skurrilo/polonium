<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

use polonium\action\Api;
use lithium\net\http\Media;

Media::type('json', array('application/json', 'text/html'), array(
	'encode' => function($data, $handler, $response) {
			return Api::mediaEncode($data, $handler, $response);
		},
	'decode' => false, // TODO try to grep filter and pagination params in decode
));
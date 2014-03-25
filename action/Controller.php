<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

namespace polonium\action;

use polonium\models\Tokens;
use lithium\util\String;
use Exception;
use InvalidArgumentException;

class Controller extends \lithium\action\Controller {

	/**
	 * cipher used for encryption in API
	 * @var string
	 */
	protected $_encryption_cipher = 'AES-128-CBC';

	/**
	 * activate type negotiation for using our own encoding defined in bootstrap.php
	 * @var array
	 */
	protected $_render = array(
		'negotiate'   => true,
	);

	/**
	 * value for api-limiting
	 * defaults to false = not authenticated
	 * @see isAuthenticated()
	 * @var array
	 */
	protected $api_limit = false;

	/**
	 * Token-Model, stored for convenience
	 * @var object
	 */
	protected $token = null;

	/**
	 * @var Response
	 */
	public $response = null;

	/**
	 * don't check auth on this actions
	 * @var array
	 */
	protected $public_actions = array();

	/**
	 * decrypt encrypted API-Call,
	 *
	 * @param mixed $encrypted contains iv, encrypted key and encrypted data. if not provided, will check request for encrypted.
	 * @return mixed
	 * @throws InvalidArgumentException
	 */
	public function _decrypt($encrypted = false) {
		if($this->token == null) {
			throw new InvalidArgumentException('Authentication missing for decryption.');
		}

		if($encrypted === false) {
			$encrypted = $this->request->get('query:encrypted');
			if($encrypted == false) {
				$encrypted = $this->request->get('data:encrypted');
				if($encrypted == false) {
					throw new InvalidArgumentException('No encrypted data provided.');
				}
			}
		}
		// separate the three parts in $encrypted
		list($iv, $enc_key, $enc_data) = explode(':', $encrypted);

		// decode the encrypted AES-key with the private-key of the Token
		$key = "";
		if(!openssl_private_decrypt(base64_decode($enc_key), $key, $this->token->private_key)) {
			return false;
		}

		// now decrypt the data with AES. $enc_data will be automatically base64-decode by openssl_decrypt
		$data = openssl_decrypt($enc_data, $this->_encryption_cipher, $key, false, base64_decode($iv));
		if($data === false) {
			return false;
		}

		// convert data into json
		$data = json_decode($data, true);
		if($data === null) {
			return false;
		}

		return $data;
	}

	/**
	 * sign the given data-array, converted as json, using the private key
	 * returns false on error
	 * return array with
	 * - signature: base64 encoded signature
	 * - data: json representation of signed data
	 *
	 * TODO: add timestamp into singed data against replay attacks
	 * 
	 * @param array $data
	 * @return array
	 * @throws InvalidArgumentException
	 */
	public function _encrypt($data) {
		if($this->token == null) {
			throw new InvalidArgumentException('Authentication missing for encryption.');
		}
		// convert array into json
		if(is_array($data)) {
			$data = json_encode($data);
		}
		$signature = false;
		if(!openssl_sign($data, $signature, $this->token->private_key)) {
			return false;
		}
		return array('signature' => base64_encode($signature), 'data' => $data);
	}

	/**
	 * add headers for browser Authentication, if Auth fails.
	 * @return array
	 */
	public function unauthorized() {
		$this->response->headers('WWW-Authenticate', 'Basic realm="API"', true);
		return $this->returnError(401, -1, 'Please Authenticate');
	}

	/**
	 * use this function in a return-statement of your controller actions to return a standardized error message for your API
	 * example:
	 * if(!$user) {
	 *   return $this->returnError(403, 4711, 'not authorized')
	 * }
	 *
	 * @param int $status_code HTTP Status code to send for this error
	 * @param int $error_code internal error code for debugging purpose
	 * @param null|string $message optional error message
	 * @param null|string $description optiona error description
	 * @return array of json-data to be sent to client
	 */
	public function returnError($status_code, $error_code, $message = null, $description = null) {
		$this->response->status('code', $status_code);
		$return = array('code' => $error_code);
		if(!is_null($message)) {
			$return['message'] = $message;
		}
		if(!is_null($description)) {
			$return['description'] = $description;
		}
		return $return;
	}

	/**
	 * intercept __invoke method of default Controller to check for API-Limiting and
	 * add a try/catch block to respond with valid json
	 *
	 * @param Request $request
	 * @param array $dispatchParams
	 * @param array $options
	 * @return Response|object
	 */
	public function __invoke($request, $dispatchParams, array $options = array()) {

		if(!in_array($request->params['action'], $this->public_actions)) {
			$this->token = Tokens::check($this->request);
			if($this->token === false) {
				return $this->renderReturn($this->unauthorized());
			}
			$this->api_limit = $this->token->incApiCount();

			// add limit-headers
			$response = $this->response;
			array_walk($this->api_limit, function ($value, $key) use ($response) {
				if(!in_array($key, array('type', 'token'))) {
					$response->headers('X-Rate-Limit-'.ucfirst($key), $value);
				}
			});

			// is this a limited user and has exceeded his limit?
			if($this->api_limit['type'] == 'limited' && $this->api_limit['remaining'] < 0) {
				// HTTP status code 429 (Too many Request) is not implemented in Lithium Router and will result in 500
				return $this->renderReturn($this->returnError(429, -1, 'Too many request in configured timeframe.'));
			}
		}

		try {
			return parent::__invoke($request, $dispatchParams, $options);
		}
		catch (Exception $e) {
			return $this->renderReturn($this->returnError(500, -1, 'Internal Server Error', $e->getMessage()));
		}
	}

	/**
	 * shortcut for rendering of result with Media-Class to return Response if not dispatching
	 * this request to parent __invoke()
	 *
	 * @param array $data
	 * @return Response
	 */
	protected function renderReturn($data) {
		$this->render(compact('data'));
		return $this->response;
	}

	/**
	 * is the current request authenticated?
	 *
	 * @return bool
	 */
	public function isAuthenticated() {
		return $this->api_limit === false ? false : true;
	}
}
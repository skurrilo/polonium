<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

namespace polonium\models;

use lithium\security\Auth;
use lithium\util\Set;
use lithium\util\String;
use MongoDate;

class Tokens extends BaseModel {

	protected $_schema = array(
		'user_id' => array('type' => 'string', 'null' => false),
		'status' => array('type' => 'string', 'null' => false, 'default' => 'active'),
		'type' => array('type' => 'string', 'null' => false, 'default' => 'limited'),
		'access_token' => array('type' => 'string', 'null' => false),
		'public_key' => array('type' => 'string', 'null' => false),
		'private_key' => array('type' => 'string', 'null' => false),
		'api.limit' => array('type' => 'integer', 'null' => false, 'default' => 500),
		'api.count' => array('type' => 'integer', 'null' => false, 'default' => 0),
		'api.started' => array('type' => 'datetime', 'null' => false, 'default' => 1),
		'api.timeslot' => array('type' => 'int', 'null' => false, 'default' => 86400),
	);

	public static $_types = array(
		'limited' => 'call-limited Token',
		'unlimited' => 'unlimited Token',
	);

	/**
	 * disable versions for auth token
	 * @var array
	 */
	protected $_meta = array(
		'versions' => false,
	);

	public function getApiLimit($entity) {
		return (int) $entity->api->limit;
	}

	public function getApiRemaining($entity) {
		return (int) $entity->api->limit - $entity->api->count;
	}

	public function getApiReset($entity) {
		$next = $entity->getApiStarted() + $entity->api->timeslot;
		return $next - time();
	}

	public function getId($entity) {
		return (string) $entity->_id;
	}

	public function getApiStarted($entity) {
		$started = $entity->api->started;
		if($started instanceof MongoDate) {
			$started = $started->sec;
		}
		return (int) $started;
	}

	public function getType($entity) {
		return $entity->type;
	}

	/**
	 * @param Tokens $entity
	 * @param int $amount
	 */
	public function incApiCount($entity, $amount = 1) {
		$type = $entity->getType();
		if($type == 'limited') {
			$started = $entity->getApiStarted();
			if($started == 0 || time() > ($started + $entity->api->timeslot)) {
				$entity->api->started = new MongoDate();
				$entity->api->count = 0;
			}
			$entity->api->count += $amount;
			$entity->save();

			$remaining = $entity->getApiRemaining();
			$reset = $entity->getApiReset();
			$limit = $entity->getApiLimit();
		}
		return compact('limit', 'remaining', 'reset', 'type');
	}

	public static function check($request) {
		/**
		 * @var Tokens
		 */
		$access_token = Auth::check('api', $request, array('writeSession' => false, 'checkSession' => false));
		if($access_token === false) {
			return false;
		}
		$conditions = array(
			'access_token' => $access_token,
			'status' => 'active',
		);

		$token = Tokens::find('first', compact('conditions'));
		if($token === false) {
			return false;
		}
		return $token;
	}

	/**
	 * inits an access-token for api. accepts additional-data in first param. options can be
	 *
	 * - unlimited: if set to true, the type of the api-token will be set to unlimited
	 * - openssl.*: will be passed to openssl_pkey_new() as params. defaults are
	 *   - digest_alg: sha512
	 *   - private_key_bits: 1024
	 *   - private_key_type: OPENSSL_KEYTYPE_RSA
	 *
	 * @param array $data
	 * @param array $options
	 * @return bool|object
	 */
	public static function init(array $data, array $options = array()) {
		$defaults = array(
			'unlimited' => false,
			'openssl.digest_alg' => 'sha512',
			'openssl.private_key_bits' => 1024,
			'openssl.private_key_type' => OPENSSL_KEYTYPE_RSA,
		);
		$options += $defaults;
		$options = Set::expand($options);

		if(empty($data['private_key']) or empty($data['public_key'])) {
			$key = openssl_pkey_new($options['openssl']);
			$private_key = "";
			openssl_pkey_export($key, $private_key);
			$public_key = openssl_pkey_get_details($key);
			$data['private_key'] = $private_key;
			$data['public_key'] = $public_key['key'];
		}
		if(empty($data['access_token'])) {
			$data['access_token'] = String::uuid();
		}
		if($options['unlimited'] === true) {
			$data['type'] = 'unlimited';
		}
		$token = static::create($data);
		if (!$token->save()) {
			return false;
		}
		return $token;
	}
}
<?php
/**
 * polonium: lithium webservice foundation.
 *
 * @copyright     Copyright 2014, brünsicke.com GmbH (http://bruensicke.com)
 * @license       http://opensource.org/licenses/BSD-3-Clause The BSD License
 */

namespace polonium\models;

/**
 * Users model
 */
class Users extends BaseModel {

	/**
	 * Custom status options
	 *
	 * @var array
	 */
	public static $_status = array(
		'active' => 'active',
		'inactive' => 'inactive',
		'suspended' => 'suspended',
		'deleted' => 'deleted',
	);

	/**
	 * Custom type options
	 *
	 * @var array
	 */
	public static $_types = array(
		'admin' => 'Administrator',
		'api' => 'API User',
		'user' => 'User',
	);

	/**
	 * Stores the data schema.
	 *
	 * login lookup via `name` and `password`.
	 * register with `email` and `password` (`name` will get value of `email`)
	 *
	 * @see lithium\data\Model
	 */
	protected $_schema = array(
		'email' => array('type' => 'string', 'default' => '', 'null' => false),
		'password' => array('type' => 'string', 'default' => '', 'null' => false),
		'last_ip' => array('type' => 'string', 'null' => false),
		'lastactive' => array('type' => 'datetime', 'null' => false),
		// TODO: birthday, address, newsletter, security-tokens, connections, permissions
	);

	/**
	 * Criteria for data validation.
	 *
	 * @see lithium\data\Model::$validates
	 * @see lithium\util\Validator::check()
	 * @var array
	 */
	public $validates = array(
		'name' => array(
			array('notEmpty', 'message' => 'a user id is required.'),
			array(
				'alphaNumeric',
				'message' => 'only numbers and letters are allowed for your username.'
			),
			array(
				'lengthBetween',
				'options' => array(
					'min' => 1,
					'max' => 250
				),
				'message' => 'please provide a user id.'
			),
			array(
				'isUnique', 'message' => 'username already taken.',
				'on' => array('create', 'register')
			),
		),
		'password' => array(
			array('notEmpty', 'message' => 'a password is required.'),
		),
		'email' => array(
			array('email', 'message' => 'please provide a valid email address.'),
			array(
				'isUnique', 'message' => 'email already in use.',
				'on' => array('create', 'register')
			),
		),
	);

	public function tokens($entity) {
		$conditions = array('status' => 'active', 'user_id' => $entity->id());
		$tokens = Tokens::find('all', compact('conditions'));
		return $tokens;
	}

	/**
	 * updates the lastactive field of an entity to lastactive
	 *
	 * @param object $entity instance of current Record
	 * @param integer $lastactive optional, timestamp to use, defaults to time()
	 * @return boolean|integer timestamp that got updated or false in case of error
	 * @filter
	 */
	public function lastActive($entity, $lastactive = null) {
		global $request;
		$params = compact('entity', 'lastactive');
		return $this->_filter(__METHOD__, $params, function($self, $params) use ($request) {
			extract($params);
			$lastactive = (is_null($lastactive) || !is_scalar($lastactive))
				? time()
				: $lastactive;
			$last_ip = $request->env('REMOTE_ADDR');
			$success = $entity->updateFields(compact('lastactive', 'last_ip'), array('updated' => false));
			if (!$success) {
				return false;
			}
			return $lastactive;
		});
	}
}

?>
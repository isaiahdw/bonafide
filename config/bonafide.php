<?php defined('SYSPATH') or die('No direct script access.');

return array(

	// Group name, multiple configuration groups are supported
	'default' => array(

		// Multiple mechanisms can be added for versioned passwords, etc
		'mechanisms' => array(

			// Put your mechanisms here! The format is:
			// string $prefix => array(string $mechanism, array $config)

			// // crypt hashing
			// 'crypt' => array('Crypt', array(
			// 	// Hash type to use
			// 	'type' => 'blowfish',
			// 
			// 	// Blowfish algorithm variant: $2a$ , $2x$ or $2y$
			// 	// If starting a new project and using PHP >= 5.3.7, set this to $2y$
			// 	'blowfish_mode' => '$2a$',
			// )),

			// // pbkdf2 hashing
			// 'pbkdf2' => array('PBKDF2', array(
			// 
			// 	// Hash type to hash algorithm use
			// 	'type' => 'sha1',
			// 
			// 	// number of iterations to use
			// 	'iterations' => 1000,
			// 
			// 	// length of derived key to create
			// 	'length' => 40,
			// )),

			// // basic HMAC hashing
			// 'hash' => array('Hash', array(
			// 	// Hash type to use when calling hash_hmac()
			// 	'type' => 'sha256',
			// 
			// 	// Shared secret HMAC key
			// 	'key' => 'put your shared secret key here!',
			// )),

			// // legacy (v3.0) Auth module hashing
			// 'legacy' => array('Legacy'),
		),
	),
);

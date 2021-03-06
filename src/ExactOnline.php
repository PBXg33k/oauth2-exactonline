<?php
namespace Pbxg33k\OAuth2\Client\Provider;

use League\OAuth2\Client\Entity\User;
use League\OAuth2\Client\Token\AccessToken;
use League\OAuth2\Client\Provider\AbstractProvider;

class ExactOnline extends AbstractProvider
{
	const BASE_DOMAIN = "https://start.exactonline.nl";

	public $token;

	public function __construct($options)
	{
		parent::__construct($options);
		$this->headers = [
			'Accept' => 'application/json',
		];
	}

	public function urlAuthorize()
	{
		return self::BASE_DOMAIN.'/api/oauth2/auth';
	}

	public function urlAccessToken()
	{
		return self::BASE_DOMAIN.'/api/oauth2/token';
	}

	public function urlUserDetails(AccessToken $token)
	{
		return self::BASE_DOMAIN.'/api/v1/current/Me?access_token='.$token;
	}

	public function userDetails($response, AccessToken $token)
	{
		$response = $response->d->results[0];
		$user = new User();

		$user->exchangeArray([
			'uid' => $response->UserID,
            'name' => $response->FullName,
            'firstname' => $response->FirstName,
            'lastname' => $response->LastName,
            'email' => $response->Email,
            'imageurl' => $response->PictureUrl,
            'locale' => $response->LanguageCode
		]);

		return $user;
	}

	public function userUid($response, AccessToken $token)
	{
		return $response->UserID;
	}

	public function currentDivision($response, AccessToken $token)
	{
		$response = $response->d->results[0];
		return $response->CurrentDivision;
	}

	public function fetchUserDetails(AccessToken $token)
	{
		$this->token = $token;
		return parent::fetchUserDetails($token);
	}

	public function fetch($url, AccessToken $token)
	{
		$this->token = $token;
		// The second argument is required or else the server will return XML
		return $this->fetchProviderData($url, ['Accept'=>'application/json']);
	}

	public function fetchCurrentDivision(AccessToken $token)
	{
		$userDetails = json_decode($this->fetchUserDetails($token));
		return $this->currentDivision($userDetails, $token);
	}

	public function getToken()
	{
		return $this->token;
	}

}
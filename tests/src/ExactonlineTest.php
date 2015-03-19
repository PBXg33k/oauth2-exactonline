<?php
namespace Pbxg33k\OAuth2\Client\Test\Provider;

use Pbxg33k\OAuth2\Client\Provider\ExactOnline;
use League\OAuth2\Client\Token\AccessToken;
use Mockery as m;

class ExactonlineTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new Exactonline([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_secret',
            'redirectUri' => 'none',
        ]);
    }

    public function tearDown()
    {
        m::close();
        parent::tearDown();
    }

    public function testAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        parse_str($uri['query'], $query);

        $this->assertArrayHasKey('client_id', $query);
        $this->assertArrayHasKey('redirect_uri', $query);
        $this->assertArrayHasKey('state', $query);
        $this->assertArrayHasKey('scope', $query);
        $this->assertNotNull($this->provider->state);
    }

    public function testUrlAccessToken()
    {
        $url = $this->provider->urlAccessToken();
        $uri = parse_url($url);

        $this->assertEquals('/api/oauth2/token', $uri['path']);
    }

    public function testUrlUserDetails()
    {
        $token = new AccessToken(['access_token' => 'fake']);

        $url = $this->provider->urlUserDetails($token);
        $uri = parse_url($url);

        $this->assertEquals('/api/v1/current/Me', $uri['path']);
        $this->assertArrayHasKey('query', $uri);
    }

    public function testGetAccessToken()
    {
        $response = m::mock('Guzzle\Http\Message\Response');
        $response->shouldReceive('getBody')->times(1)->andReturn(
            '{"access_token": "mock_access_token", "expires_in": 3600, "refresh_token": "mock_refresh_token"}'
        );

        $client = m::mock('Guzzle\Service\Client');
        $client->shouldReceive('setBaseUrl')->times(1);
        $client->shouldReceive('post->send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);

        $this->assertEquals('mock_access_token', $token->accessToken);
        $this->assertEquals('mock_refresh_token', $token->refreshToken);
        $this->assertLessThanOrEqual(time() + 3600, $token->expires);
        $this->assertGreaterThanOrEqual(time(), $token->expires);
    }
}

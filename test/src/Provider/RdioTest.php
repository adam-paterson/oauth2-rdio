<?php

namespace AdamPaterson\OAuth2\Client\Test;

use Mockery as m;

class RdioTest extends \PHPUnit_Framework_TestCase
{
    protected $provider;

    protected function setUp()
    {
        $this->provider = new \AdamPaterson\OAuth2\Client\Provider\Rdio([
            'clientId' => 'mock_client_id',
            'clientSecret' => 'mock_client_secret',
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
        $this->assertArrayHasKey('response_type', $query);
        $this->assertArrayHasKey('approval_prompt', $query);
        $this->assertNotNull($this->provider->getState());
    }

    public function testScopes()
    {
        $options = ['scope' => [uniqid(), uniqid()]];
        $url = $this->provider->getAuthorizationUrl($options);
        $this->assertContains(urlencode(implode(',', $options['scope'])), $url);
    }

    public function testGetAuthorizationUrl()
    {
        $url = $this->provider->getAuthorizationUrl();
        $uri = parse_url($url);
        $this->assertEquals('/oauth2/authorize', $uri['path']);
    }

    public function testGetBaseAccessTokenUrl()
    {
        $params = [];
        $url = $this->provider->getBaseAccessTokenUrl($params);
        $uri = parse_url($url);
        $this->assertEquals('/oauth2/token', $uri['path']);
    }


    public function testGetAccessToken()
    {
        $response = m::mock('Psr\Http\Message\ResponseInterface');
        $response->shouldReceive('getBody')->andReturn('{"access_token":"mock_access_token", "scope":"repo,gist", "token_type":"bearer"}');
        $response->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $response->shouldReceive('getStatusCode')->andReturn(200);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')->times(1)->andReturn($response);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code',
            ['code' => 'mock_authorization_code']);
        $this->assertEquals('mock_access_token', $token->getToken());
        $this->assertNull($token->getExpires());
        $this->assertNull($token->getRefreshToken());
        $this->assertNull($token->getResourceOwnerId());
    }

    public function testUserData()
    {
        $icon250 = uniqid();
        $firstName = uniqid();
        $baseIcon = uniqid();
        $gender = uniqid();
        $url = uniqid();
        $icon500 = uniqid();
        $id = uniqid();
        $lastName = uniqid();
        $libraryVersion = rand(0, 9999);
        $isProtected = true;
        $dynamicIcon = uniqid();
        $type = uniqid();
        $icon = uniqid();

        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn('access_token=mock_access_token&expires=3600&refresh_token=mock_refresh_token&otherKey={1234}');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'application/x-www-form-urlencoded']);
        $postResponse->shouldReceive('getStatusCode')->andReturn(200);
        $userResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $userResponse->shouldReceive('getBody')->andReturn('{"status": "ok","result": {"icon250": "'.$icon250.'","firstName": "'.$firstName.'","baseIcon": "'.$baseIcon.'","gender": "'.$gender.'","url": "'.$url.'","icon500": "'.$icon500.'","key": "'.$id.'","lastName": "'.$lastName.'","libraryVersion": '.$libraryVersion.',"isProtected": '.$isProtected.',"dynamicIcon": "'.$dynamicIcon.'","type": "'.$type.'","icon": "'.$icon.'"}}');
        $userResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $userResponse->shouldReceive('getStatusCode')->andReturn(200);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(2)
            ->andReturn($postResponse, $userResponse);
        $this->provider->setHttpClient($client);

        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
        $user = $this->provider->getResourceOwner($token);
        $this->assertEquals($icon250, $user->getIcon250());
        $this->assertEquals($icon250, $user->toArray()['result']['icon250']);
        $this->assertEquals($firstName, $user->getFirstname());
        $this->assertEquals($firstName, $user->toArray()['result']['firstName']);
        $this->assertEquals($baseIcon, $user->getBaseIcon());
        $this->assertEquals($baseIcon, $user->toArray()['result']['baseIcon']);
        $this->assertEquals($gender, $user->getGender());
        $this->assertEquals($gender, $user->toArray()['result']['gender']);
        $this->assertEquals($url, $user->getUrl());
        $this->assertEquals($url, $user->toArray()['result']['url']);
        $this->assertEquals($icon500, $user->getIcon500());
        $this->assertEquals($icon500, $user->toArray()['result']['icon500']);
        $this->assertEquals($id, $user->getId());
        $this->assertEquals($id, $user->toArray()['result']['key']);
        $this->assertEquals($lastName, $user->getLastName());
        $this->assertEquals($lastName, $user->toArray()['result']['lastName']);
        $this->assertEquals($libraryVersion, $user->getLibraryVersion());
        $this->assertEquals($libraryVersion, $user->toArray()['result']['libraryVersion']);
        $this->assertEquals($isProtected, $user->isProtected());
        $this->assertEquals($isProtected, $user->toArray()['result']['isProtected']);
        $this->assertEquals($dynamicIcon, $user->getDynamicIcon());
        $this->assertEquals($dynamicIcon, $user->toArray()['result']['dynamicIcon']);
        $this->assertEquals($type, $user->getType());
        $this->assertEquals($type, $user->toArray()['result']['type']);
        $this->assertEquals($icon, $user->getIcon());
        $this->assertEquals($icon, $user->toArray()['result']['icon']);
    }

    /**
     * @expectedException League\OAuth2\Client\Provider\Exception\IdentityProviderException
     */
    public function testExceptionThrownWhenErrorObjectReceived()
    {
        $message = uniqid();
        $status = rand(400,600);
        $postResponse = m::mock('Psr\Http\Message\ResponseInterface');
        $postResponse->shouldReceive('getBody')->andReturn(' {"error_description":"'.$message.'"}');
        $postResponse->shouldReceive('getHeader')->andReturn(['content-type' => 'json']);
        $postResponse->shouldReceive('getStatusCode')->andReturn($status);
        $client = m::mock('GuzzleHttp\ClientInterface');
        $client->shouldReceive('send')
            ->times(1)
            ->andReturn($postResponse);
        $this->provider->setHttpClient($client);
        $token = $this->provider->getAccessToken('authorization_code', ['code' => 'mock_authorization_code']);
    }

}
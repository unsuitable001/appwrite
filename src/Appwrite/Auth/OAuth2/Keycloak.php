<?php

namespace Appwrite\Auth\OAuth2;

use Appwrite\Auth\OAuth2;

class Keycloak extends OAuth2
{
    /**
     * @var string
     */
    // Pointing to the local instance.
    // TODO: Need a method to change this from the UI.
    private $endpoint = 'http://localhost:8080/auth/realms/betterdata_demo/protocol/openid-connect/';

    /**
     * @var array
     */
    protected $user = [];

    /**
     * @var array
     */

    // scopes are optional in keycloak
    protected $scopes = [];

    /**
     * @return string
     */
    public function getName():string
    {
        return 'keycloak';
    }

    /**
     * @return string
     */
    public function getLoginURL():string
    {
        // KeyCloak expects a non-encoded url
        return $this->endpoint. 'auth?redirect_uri='. $this->callback. '&'. \http_build_query([
            'client_id' => $this->appID,
            'response_type' => 'code',
            'login' => 'true',
            'state' => \json_encode($this->state)
        ]);
    }

    /**
     * @param string $code
     *
     * @return string
     */
    public function getAccessToken(string $code):string
    {
        $accessToken = $this->request(
            'POST',
            $this->endpoint. 'token',
            ['Content-Type: application/x-www-form-urlencoded'],
            \http_build_query([
                'grant_type' => 'authorization_code',
                'client_id' => $this->appID,
                'redirect_uri' => 'http://localhost/v1/account/sessions/oauth2/callback/keycloak/618ccd94911c9',
                'client_secret' => $this->appSecret,
                'code' => $code
            ])
        );

        $output = \json_decode($accessToken, false);

        if (isset($output['access_token'])) {
            return $output['access_token'];
        }

        return '';
    }

    /**
     * @param $accessToken
     *
     * @return string
     */
    public function getUserID(string $accessToken):string
    {
        $user = $this->getUser($accessToken);

        if (isset($user['sub'])) {
            return $user['sub'];
        }

        return '';
    }

    /**
     * @param $accessToken
     *
     * @return string
     */
    public function getUserEmail(string $accessToken):string
    {
        $user = $this->getUser($accessToken);

        if (isset($user['email']) && isset($user['email_verified']) && $user['email_verified']) {
            return $user['email'];
        }

        return '';
    }

    /**
     * @param $accessToken
     *
     * @return string
     */
    public function getUserName(string $accessToken):string
    {
        $user = $this->getUser($accessToken);

        if (isset($user['preferred_username'])) {
            return $user['preferred_username'];
        }

        return '';
    }

    /**
     * @param string $accessToken
     *
     * @return array
     */
    protected function getUser(string $accessToken)
    {
        if (empty($this->user)) {
            $this->user = \json_decode($this->request('POST', $this->endpoint. 'userinfo', ['Content-Type: application/x-www-form-urlencoded'],
            \http_build_query([
                'access_token' => $accessToken
            ])));
        }

        return $this->user;
    }
}

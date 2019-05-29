<?php
/**
 * Auth controller
 */
namespace Application;

use Bluz\Controller\Controller;
use Bluz\Proxy\Config;
use Bluz\Proxy\Messages;
use Bluz\Proxy\Response;
use Bluz\Proxy\Router;
use Hybridauth\Exception\Exception as HybridauthException;
use Hybridauth\Hybridauth;

/**
 * @param string $provider
 *
 * @return void
 */
return function ($provider = '') {
    /**
     * @var Controller $this
     */
    try {
        // Get configuration
        $config = Config::get('auth', 'hybrid');
        $provider = strtolower($provider);

        // Check provider name
        if (!array_key_exists($provider, $config['providers'])) {
            throw new Exception('Invalid provider name');
        }

        $config['callback'] = Router::getFullUrl('auth', 'auth', ['provider' => $provider]);

        // Feed configuration array to Hybridauth
        $hybridauth = new Hybridauth($config);

        // Attempt to authenticate users with a provider by name
        $adapter = $hybridauth->authenticate(ucfirst($provider));

        // Returns a boolean of whether the user is connected with provider
        if ($adapter->isConnected()) {
            // Retrieve the user's profile
            $profile = $adapter->getUserProfile();

            // Access token from provider
            $accessToken = $adapter->getAccessToken();

            // Check authRow
            $authRow = Auth\Table::getAuthRow($provider, $profile->identifier);

            // Inspect profile's public attributes
            if ($this->user()) {
                if ($authRow) {
                    Messages::addNotice('You have already linked to `%s`', $provider);
                } else {
                    // Create token and link it with user profile
                    $authRow = new Auth\Row();
                    $authRow->userId = $this->user()->getId();
                    $authRow->provider = $provider;
                    $authRow->foreignKey = $profile->identifier;
                    $authRow->tokenSecret = $accessToken['access_token_secret'] ?? '';
                    $authRow->tokenType = $accessToken['token_type'] ?? Auth\Table::TYPE_ACCESS;
                    Messages::addNotice('Your account was linked to `%s` successfully!', $provider);
                }
                // Update access token
                $authRow->token = $accessToken['access_token'];
                $authRow->save();
                Response::redirectTo('users', 'profile');
            } elseif ($authRow) {
                // Try to login
                $user = Users\Table::findRow($authRow->userId);
                Auth\Table::tryLogin($user);
                Messages::addNotice('You are signed');
            } else {
                // User not found
                Messages::addError('Not found linked profile');
                Response::redirectTo('users', 'signin');
            }

            // Disconnect the adapter
            $adapter->disconnect();
        }
    } catch (HybridauthException $e) {
        Messages::addError($e->getMessage());
    }
    Response::redirectTo('index');
};

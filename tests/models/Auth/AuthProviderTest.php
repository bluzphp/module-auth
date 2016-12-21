<?php
/**
 * @copyright Bluz PHP Team
 * @link https://github.com/bluzphp/skeleton
 */

/**
 * @namespace
 */
namespace Application\Tests\Auth;

use Application\Auth\AuthProvider;
use Application\Tests\ControllerTestCase;

/**
 * Class AuthProviderTest
 * @author yuklia <yuliakostrikova@gmail.com>
 * @package Application\Tests\Auth
 */
class AuthProviderTest extends ControllerTestCase
{
    /**
     * @expectedException \Exception
     */
    public function testProviderNotFound()
    {
        new AuthProvider('fake_data');
    }

    /**
     * @expectedException \Exception
     */
    public function testFailureHybridProvider()
    {
        $provider = new AuthProvider('olo');
        self::assertInstanceOf('\Hybrid_Provider_Adapter', $provider->authenticate('olo'));
    }
}

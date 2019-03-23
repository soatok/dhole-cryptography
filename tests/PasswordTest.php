<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Password;

/**
 * Class PasswordTest
 * @package Soatok\DholeCrypto\Tests
 */
class PasswordTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testPwhash()
    {
        $symKey = SymmetricKey::generate();
        $password = new HiddenString("correct horse battery staple");
        $hasher = new Password($symKey);

        $hash = $hasher->hash($password);
        $this->assertTrue($hasher->verify($password, $hash));

        $hash2 = $hasher->hash($password, "userid=12345");
        $this->assertTrue($hasher->verify($password, $hash2, "userid=12345"));

        try {
            $hasher->verify($password, $hash, "userid=12345");
            $this->fail("Incorrect additional associated data should cause an exception");
        } catch (CryptoException $ex) {
        }
        try {
            $hasher->verify($password, $hash2);
            $this->fail("Incorrect additional associated data should cause an exception");
        } catch (CryptoException $ex) {
        }
    }
}
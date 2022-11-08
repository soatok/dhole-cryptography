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
    public function setUp(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->fail('Libsodium not loaded');
        }
    }

    public function testNeedsRehash()
    {
        $symKey = SymmetricKey::generate();
        $password = new HiddenString("correct horse battery staple");
        $legacy = new Password($symKey, ['mem' => 1 << 14, 'ops' => 3]); // m = 16 MB, t = 3
        $hasher = new Password($symKey, ['mem' => 1 << 16, 'ops' => 2]); // m = 64 MB, t = 2

        $pwhash = $legacy->hash($password);
        $this->assertTrue($hasher->needsRehash($pwhash));
        $this->assertFalse($legacy->needsRehash($pwhash));
        $this->assertFalse($legacy->needsRehash($pwhash));
        $this->assertTrue($hasher->needsRehash($pwhash));

        $pwhash = $hasher->hash($password);
        $this->assertFalse($hasher->needsRehash($pwhash));
        $this->assertTrue($legacy->needsRehash($pwhash));
        $this->assertTrue($legacy->needsRehash($pwhash));
        $this->assertFalse($hasher->needsRehash($pwhash));
    }

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
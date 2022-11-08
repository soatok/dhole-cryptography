<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Tests;

use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Soatok\DholeCrypto\Key\AsymmetricPublicKey;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Keyring;
use Soatok\DholeCrypto\Symmetric;

/**
 * Class KeyringTest
 * @package Soatok\DholeCrypto\Tests
 */
class KeyringTest extends TestCase
{
    /** @var Keyring $ring */
    protected $ring;

    /** @var Keyring $wrapped */
    protected $wrapped;

    public function setUp(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->fail('Libsodium not loaded');
        }
        $this->ring = new Keyring();
        $this->wrapped = new Keyring(SymmetricKey::generate());
    }

    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testAsymmetricSecretKey()
    {
        $key = AsymmetricSecretKey::generate();
        $stored = $this->ring->save($key);
        $wrapped = $this->wrapped->save($key);

        $this->assertTrue(\is_string($stored));
        $this->assertTrue(Symmetric::isValidCiphertext($wrapped));

        $load1 = $this->ring->load($stored);
        $this->assertInstanceOf(AsymmetricSecretKey::class, $load1);
        $load2 = $this->wrapped->load($wrapped);
        $this->assertInstanceOf(AsymmetricSecretKey::class, $load2);

        try {
            $this->ring->load($wrapped);
            $this->fail("Attempted to load a keywrapped key without a keywrap key.");
        } catch (CryptoException $ex) {
        }
    }

    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testAsymmetricPublicKey()
    {
        $secret = AsymmetricSecretKey::generate();
        $key = $secret->getPublicKey();

        $stored = $this->ring->save($key);
        $wrapped = $this->wrapped->save($key);

        $this->assertTrue(\is_string($stored));
        $this->assertTrue(Symmetric::isValidCiphertext($wrapped));

        $load1 = $this->ring->load($stored);
        $this->assertInstanceOf(AsymmetricPublicKey::class, $load1);
        $load2 = $this->wrapped->load($wrapped);
        $this->assertInstanceOf(AsymmetricPublicKey::class, $load2);

        try {
            $this->ring->load($wrapped);
            $this->fail("Attempted to load a keywrapped key without a keywrap key.");
        } catch (CryptoException $ex) {
        }
    }

    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testSymmetricKey()
    {
        $key = SymmetricKey::generate();
        $stored = $this->ring->save($key);
        $wrapped = $this->wrapped->save($key);

        $this->assertTrue(\is_string($stored));
        $this->assertTrue(Symmetric::isValidCiphertext($wrapped));

        $load1 = $this->ring->load($stored);
        $this->assertInstanceOf(SymmetricKey::class, $load1);
        $load2 = $this->wrapped->load($wrapped);
        $this->assertInstanceOf(SymmetricKey::class, $load2);
        try {
            $this->ring->load($wrapped);
            $this->fail("Attempted to load a keywrapped key without a keywrap key.");
        } catch (CryptoException $ex) {
        }
    }
}

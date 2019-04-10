<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\ConstantTime\Binary;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\Asymmetric;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use Soatok\DholeCrypto\Exceptions\CryptoException;

/**
 * Class AsymmetricTest
 */
class AsymmetricTest extends TestCase
{
    public function setUp(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->fail('Libsodium not loaded');
        }
    }

    /**
     * @throws \SodiumException
     */
    public function testKeyExchange()
    {
        $alice = AsymmetricSecretKey::generate();
        $bob = AsymmetricSecretKey::generate();

        $a2b = Asymmetric::keyExchange($alice, $bob->getPublicKey(), true);
        $b2a = Asymmetric::keyExchange($bob, $alice->getPublicKey(), false);

        $this->assertSame(
            Base64UrlSafe::encode($a2b->getRawKeyMaterial()),
            Base64UrlSafe::encode($b2a->getRawKeyMaterial())
        );

        $a3b = Asymmetric::keyExchange($alice, $bob->getPublicKey(), false);
        $b3a = Asymmetric::keyExchange($bob, $alice->getPublicKey(), true);

        $this->assertSame(
            Base64UrlSafe::encode($a3b->getRawKeyMaterial()),
            Base64UrlSafe::encode($b3a->getRawKeyMaterial())
        );
        $this->assertNotSame(
            Base64UrlSafe::encode($a2b->getRawKeyMaterial()),
            Base64UrlSafe::encode($b3a->getRawKeyMaterial())
        );
        $this->assertNotSame(
            Base64UrlSafe::encode($a3b->getRawKeyMaterial()),
            Base64UrlSafe::encode($b2a->getRawKeyMaterial())
        );
    }
    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testEncryptDecrypt()
    {
        $aSecret = AsymmetricSecretKey::generate();
        $aPublic = $aSecret->getPublicKey();
        $bSecret = AsymmetricSecretKey::generate();
        $bPublic = $bSecret->getPublicKey();

        $message = new HiddenString(
            "This is a secret message for your ears only: UwU"
        );

        $cipher = Asymmetric::encrypt($message, $bPublic, $aSecret);
        $decrypt = Asymmetric::decrypt($cipher, $bSecret, $aPublic);

        $this->assertSame($message->getString(), $decrypt->getString());
    }

    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testSealUnseal()
    {
        $secret = AsymmetricSecretKey::generate();
        $public = $secret->getPublicKey();

        $message = new HiddenString(
            "This is a secret message for your ears only: UwU"
        );
        $sealed = Asymmetric::seal($message, $public);
        $unseal = Asymmetric::unseal($sealed, $secret);
        $this->assertSame($message->getString(), $unseal->getString());
    }

    /**
     * @throws \SodiumException
     */
    public function testSignVerify()
    {
        $secret = AsymmetricSecretKey::generate();
        $public = $secret->getPublicKey();

        $message = "I certify that you have paid your $350 awoo fine";
        $sig = Asymmetric::sign($message, $secret);
        $this->assertSame(128, Binary::safeStrlen($sig));
        $this->assertTrue(Asymmetric::verify($message, $public, $sig));
    }
}

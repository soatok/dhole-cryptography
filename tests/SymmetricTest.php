<?php
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Symmetric;

/**
 * Class SymmetricTest
 * @package Furified\Tests\Engine\Cryptography
 */
class SymmetricTest extends TestCase
{
    /**
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function testEncryptDecrypt()
    {
        $key = SymmetricKey::generate();

        $message = new HiddenString('This is a secret, okay?');

        $encrypted = Symmetric::encrypt($message, $key);
        $decrypted = Symmetric::decrypt($encrypted, $key);

        $this->assertSame(
            $message->getString(),
            $decrypted->getString(),
            'Encryption is not invertible! Or a bug in our high-level protocol.'
        );

        $aad = 'random:' . sodium_bin2hex(random_bytes(32));
        $encWithAd = Symmetric::encryptWithAd($message, $key, $aad);
        $this->assertSame(
            $message->getString(),
            Symmetric::decryptWithAd($encWithAd, $key, $aad)->getString(),
            'Encryption is not invertible! Or a bug in our high-level protocol.'
        );
        try {
            Symmetric::decrypt($encWithAd, $key);
            $this->fail('Silent failure not tolerated');
        } catch (CryptoException $ex) {
        }
        try {
            Symmetric::decryptWithAd($encrypted, $key, $aad);
            $this->fail('Silent failure not tolerated');
        } catch (CryptoException $ex) {
        }
    }
}

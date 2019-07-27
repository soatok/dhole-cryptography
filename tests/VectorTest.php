<?php
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\ConstantTime\Base64UrlSafe;
use ParagonIE\HiddenString\HiddenString;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\{Asymmetric, AsymmetricFile, Keyring, Symmetric};
use Soatok\DholeCrypto\Key\{
    AsymmetricSecretKey,
    AsymmetricPublicKey,
    SymmetricKey
};

/**
 * Class VectorTest
 * @package Soatok\DholeCrypto\Tests
 */
class VectorTest extends TestCase
{
    private $testVectors = [];
    private $asymmetric = [];
    private $symKeys = [];

    public function setUp(): void
    {
        $testVectors = json_decode(
            file_get_contents(dirname(__DIR__) . '/docs/test-vectors.json'),
            true
        );

        foreach ($testVectors['symmetric']['keys'] as $id => $encoded) {
            $this->symKeys[$id] = new SymmetricKey(
                new HiddenString(
                    Base64UrlSafe::decode($encoded)
                )
            );
        }
        foreach ($testVectors['asymmetric']['participants'] as $id => $data) {
            $secret = new AsymmetricSecretKey(
                new HiddenString(
                    Base64UrlSafe::decode($data['secret-key'])
                )
            );
            $public = new AsymmetricPublicKey(
                new HiddenString(
                    Base64UrlSafe::decode($data['public-key'])
                )
            );
            $this->asymmetric[$id] = [
                'secret-key' => $secret,
                'public-key' => $public
            ];
        }

        $this->testVectors = $testVectors;
    }

    public function testAsymmetricEncrypt()
    {
        foreach ($this->testVectors['asymmetric']['encrypt'] as $index => $test) {
            $senderPublic = $this->asymmetric[$test['sender']]['public-key'];
            $recipientSecret = $this->asymmetric[$test['recipient']]['secret-key'];

            $plain = Asymmetric::decrypt(
                $test['encrypted'],
                $recipientSecret,
                $senderPublic
            );
            $this->assertSame(
                $test['decrypted'],
                $plain->getString()
            );
        }
    }

    /**
     * @throws \Soatok\DholeCrypto\Exceptions\CryptoException
     * @throws \Soatok\DholeCrypto\Exceptions\FilesystemException
     * @throws \SodiumException
     */
    public function testAsymmetricFile()
    {
        /** @var AsymmetricPublicKey $publicKey */
        $publicKey = (new Keyring())->load(
            $this->testVectors['asymmetric-file-sign']['public-key']
        );
        foreach ($this->testVectors['asymmetric-file-sign']['tests'] as $index => $test) {
            $file = fopen('php://temp', 'wb');
            fwrite($file, $test['contents']);
            fseek($file, 0, SEEK_SET);
            $this->assertTrue(
                AsymmetricFile::verify($file, $publicKey, $test['signature'])
            );
            fclose($file);
        }
    }

    public function testSymmetricEncrypt()
    {
        foreach ($this->testVectors['symmetric']['encrypt'] as $index => $test) {
            $key = $this->symKeys[$test['key']];
            $aad = $test['aad'];
            $cipher = $test['encrypted'];
            try {
                $plain = Symmetric::decryptWithAd($cipher, $key, $aad);
            } catch (\Throwable $ex) {
                var_dump($index);
                throw $ex;
            }
            $this->assertSame(
                $test['decrypted'],
                $plain->getString()
            );
        }
    }
}
<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\AsymmetricFile;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;

/**
 * Class AsymmetricFileTest
 * @package Soatok\DholeCrypto\Tests
 */
class AsymmetricFileTest extends TestCase
{
    public function setUp(): void
    {
        if (!\extension_loaded('sodium')) {
            $this->fail('Libsodium not loaded');
        }
    }

    /**
     * @throws \Soatok\DholeCrypto\Exceptions\FilesystemException
     * @throws \SodiumException
     */
    public function testSign()
    {
        $secret = AsymmetricSecretKey::generate();
        $public = $secret->getPublicKey();

        $buffer = Base32::encodeUnpadded(random_bytes(10000));
        $fp = fopen('php://temp', 'wb');
        fwrite($fp, $buffer);

        $signature = AsymmetricFile::sign($fp, $secret);
        $this->assertTrue(AsymmetricFile::verify($fp, $public, $signature));
    }
}

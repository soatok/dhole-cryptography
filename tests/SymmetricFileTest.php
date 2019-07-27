<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Tests;

use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;
use Soatok\DholeCrypto\SymmetricFile;

/**
 * Class SymmetricFileTest
 * @package Soatok\DholeCrypto\Tests
 */
class SymmetricFileTest extends TestCase
{
    /**
     * @throws \Soatok\DholeCrypto\Exceptions\FilesystemException
     * @throws \SodiumException
     */
    public function testHash()
    {
        $random = random_bytes(32);
        foreach ([32, 64, 100, 1000, 10000] as $len) {
            $buffer = Base32::encodeUnpadded(random_bytes($len));

            $fp = fopen('php://temp', 'wb');
            fwrite($fp, $buffer);

            $a = sodium_crypto_generichash($buffer, '', 64);
            $b = SymmetricFile::hash($fp);
            $this->assertSame(bin2hex($a), bin2hex($b));

            $a = $random . sodium_crypto_generichash($random . $buffer, '', 64);
            $b = SymmetricFile::hash($fp, $random);
            $this->assertSame(bin2hex($a), bin2hex($b));
            fclose($fp);
        }
    }
}
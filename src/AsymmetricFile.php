<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use Soatok\DholeCrypto\Exceptions\FilesystemException;
use Soatok\DholeCrypto\Key\{
    AsymmetricPublicKey,
    AsymmetricSecretKey
};

/**
 * Class AsymmetricFile
 * @package Soatok\DholeCrypto
 */
class AsymmetricFile
{
    /**
     * @param string|resource $file
     * @param AsymmetricSecretKey $sk
     * @return string
     *
     * @throws Exceptions\FilesystemException
     * @throws \SodiumException
     */
    public static function sign($file, AsymmetricSecretKey $sk): string
    {
        $random = \random_bytes(32);
        $hash = SymmetricFile::hash($file, $random);
        return Base64UrlSafe::encode(
            \sodium_crypto_sign_detached(
                $hash,
                $sk->getRawKeyMaterial()
            ) . $random
        );
    }

    /**
     * @param string|resource $file
     * @param AsymmetricPublicKey $pk
     * @param string $sig
     * @return bool
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public static function verify($file, AsymmetricPublicKey $pk, string $sig): bool
    {
        $decoded = Base64UrlSafe::decode($sig);
        $signature = Binary::safeSubstr($decoded, 0, 64);
        $random = Binary::safeSubstr($decoded, 64);
        $hash = SymmetricFile::hash($file, $random);
        return \sodium_crypto_sign_verify_detached(
            $signature,
            $hash,
            $pk->getRawKeyMaterial()
        );
    }
}

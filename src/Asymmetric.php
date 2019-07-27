<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\HiddenString\HiddenString;
use ParagonIE_Sodium_Compat as NaCl;
use Soatok\DholeCrypto\Key\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};
use Soatok\DholeCrypto\Exceptions\CryptoException;

/**
 * Class Asymmetric
 * @package Soatok\DholeCrypto\Cryptography
 */
abstract class Asymmetric
{
    /**
     * @param AsymmetricSecretKey $sk
     * @param AsymmetricPublicKey $pk
     * @param bool $isClient
     * @return SymmetricKey
     * @throws \SodiumException
     */
    public static function keyExchange(
        AsymmetricSecretKey $sk,
        AsymmetricPublicKey $pk,
        bool $isClient
    ): SymmetricKey {
        if ($isClient) {
            $symmetric = NaCl::crypto_kx(
                $sk->getBirationalSecret()->getString(),
                $pk->getBirationalPublic()->getString(),
                $sk->getPublicKey()->getBirationalPublic()->getString(),
                $pk->getBirationalPublic()->getString()
            );
        } else {
            $symmetric = NaCl::crypto_kx(
                $sk->getBirationalSecret()->getString(),
                $pk->getBirationalPublic()->getString(),
                $pk->getBirationalPublic()->getString(),
                $sk->getPublicKey()->getBirationalPublic()->getString()
            );
        }
        $return = new SymmetricKey(new HiddenString($symmetric));
        sodium_memzero($symmetric);
        return $return;
    }

    /**
     * @param HiddenString $msg
     * @param AsymmetricPublicKey $pk
     * @param AsymmetricSecretKey $sk
     * @return string
     * @throws \SodiumException
     */
    public static function encrypt(
        HiddenString $msg,
        AsymmetricPublicKey $pk,
        AsymmetricSecretKey $sk
    ): string {
        return static::seal(
            new HiddenString(
                static::sign($msg->getString(), $sk) .
                $msg->getString()
            ),
            $pk
        );
    }

    /**
     * @param string $msg
     * @param AsymmetricSecretKey $sk
     * @param AsymmetricPublicKey $pk
     * @return HiddenString
     * @throws CryptoException
     * @throws \SodiumException
     */
    public static function decrypt(
        string $msg,
        AsymmetricSecretKey $sk,
        AsymmetricPublicKey $pk
    ): HiddenString {
        $decrypted = self::unseal($msg, $sk)->getString();
        $signature = Binary::safeSubstr($decrypted, 0, 128);
        $plaintext = Binary::safeSubstr($decrypted, 128);
        sodium_memzero($decrypted);
        try {
            $result = self::verify($plaintext, $pk, $signature);
            if (!$result) {
                throw new CryptoException('Invalid signature');
            }
            return new HiddenString($plaintext);
        } catch (\SodiumException $ex) {
            throw new CryptoException('Invalid signature');
        } finally {
            sodium_memzero($signature);
            sodium_memzero($plaintext);
        }
    }

    /**
     * @param HiddenString $msg
     * @param AsymmetricPublicKey $pk
     * @return string
     * @throws \SodiumException
     */
    public static function seal(HiddenString $msg, AsymmetricPublicKey $pk): string
    {
        $sk = AsymmetricSecretKey::generate();
        $sym = static::keyExchange($sk, $pk, true);
        $pub = $sk->getPublicKey()->getBirationalPublic()->getString();
        return Symmetric::encryptWithAd(
            $msg,
            $sym,
            $pub
        ) . '$' . Base64UrlSafe::encode($pub);
    }

    /**
     * @param string $sealed
     * @param AsymmetricSecretKey $sk
     * @return HiddenString
     * @throws CryptoException
     * @throws \SodiumException
     */
    public static function unseal(string $sealed, AsymmetricSecretKey $sk): HiddenString
    {
        $pos = strpos($sealed, '$');
        if ($pos === false) {
            throw new CryptoException("Invalid ciphertext: Not sealed");
        }
        $cipher = Binary::safeSubstr($sealed, 0, $pos);
        $public = Binary::safeSubstr($sealed, $pos + 1);
        $pk = Base64UrlSafe::decode($public);

        $symmetric = new SymmetricKey(new HiddenString(
            NaCl::crypto_kx(
                $sk->getBirationalSecret()->getString(),
                $pk,
                $pk,
                $sk->getPublicKey()->getBirationalPublic()->getString()
            )
        ));

        return Symmetric::decryptWithAd(
            $cipher,
            $symmetric,
            $pk
        );
    }

    /**
     * @param string $msg
     * @param AsymmetricSecretKey $sk
     * @return string
     * @throws \SodiumException
     */
    public static function sign(string $msg, AsymmetricSecretKey $sk): string
    {
        $random = \random_bytes(32);
        return Base64UrlSafe::encode(
            \sodium_crypto_sign_detached(
                $random . $msg,
                $sk->getRawKeyMaterial()
            ) . $random
        );
    }

    /**
     * @param string $msg
     * @param AsymmetricPublicKey $pk
     * @param string $sig
     * @return bool
     * @throws \SodiumException
     */
    public static function verify(string $msg, AsymmetricPublicKey $pk, string $sig): bool
    {
        $decoded = Base64UrlSafe::decode($sig);
        $signature = Binary::safeSubstr($decoded, 0, 64);
        $random = Binary::safeSubstr($decoded, 64);
        return \sodium_crypto_sign_verify_detached(
            $signature,
            $random . $msg,
            $pk->getRawKeyMaterial()
        );
    }
}

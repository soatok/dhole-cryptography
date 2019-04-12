<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

use ParagonIE\ConstantTime\{
    Base64UrlSafe,
    Binary
};
use ParagonIE\HiddenString\HiddenString;
use Soatok\DholeCrypto\Contract\CryptographicKeyInterface;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use Soatok\DholeCrypto\Key\{
    AsymmetricPublicKey,
    AsymmetricSecretKey,
    SymmetricKey
};

/**
 * Class Keyring
 * @package Soatok\DholeCrypto
 */
class Keyring
{
    const KTYPE_ASYMMETRIC_SECRET = 'ed25519sk';
    const KTYPE_ASYMMETRIC_PUBLIC = 'ed25519pk';
    const KTYPE_SYMMETRIC         = 'symmetric';

    /** @var SymmetricKey|null $keywrapKey */
    private $keywrapKey;

    /**
     * Keyring constructor.
     * @param SymmetricKey $keywrapKey
     */
    public function __construct(?SymmetricKey $keywrapKey = null)
    {
        $this->keywrapKey = $keywrapKey;
    }

    /**
     * @param string $serialized
     * @return CryptographicKeyInterface
     *
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function load(string $serialized): CryptographicKeyInterface
    {
        // If it's keywrapped, get the raw key
        if (Symmetric::isValidCiphertext($serialized)) {
            if (is_null($this->keywrapKey)) {
                throw new CryptoException(
                    "This key has been encrypted and you have not provided the keywrap key."
                );
            }
            $serialized = Symmetric::decrypt($serialized, $this->keywrapKey)->getString();
        }
        if (Binary::safeStrlen($serialized) < 9) {
            throw new CryptoException("String is too short to be a serialized key");
        }
        $header = Binary::safeSubstr($serialized, 0, 9);
        switch ($header) {
            case static::KTYPE_ASYMMETRIC_SECRET:
                return $this->loadAsymmetricSecretKey($serialized);
            case static::KTYPE_ASYMMETRIC_PUBLIC:
                return $this->loadAsymmetricPublicKey($serialized);
            case static::KTYPE_SYMMETRIC:
                return $this->loadSymmetricKey($serialized);
            default:
                throw new \TypeError('Invalid key type: ' . $header);
        }
    }

    /**
     * @param CryptographicKeyInterface $key
     * @return string
     * @throws \SodiumException
     */
    public function save(CryptographicKeyInterface $key): string
    {
        if ($key instanceof AsymmetricSecretKey) {
            return $this->keyWrap($this->saveAsymmetricSecretKey($key));
        }
        if ($key instanceof AsymmetricPublicKey) {
            return $this->keyWrap($this->saveAsymmetricPublicKey($key));
        }
        if ($key instanceof SymmetricKey) {
            return $this->keyWrap($this->saveSymmetricKey($key));
        }
        throw new \TypeError('Invalid key type: ' . \get_class($key));
    }

    /**
     * @param string $serialized
     * @return array
     * @throws \SodiumException
     */
    protected function getComponents(string $serialized): array
    {
        $header = Binary::safeSubstr($serialized, 0, 9);
        $decoded = Base64UrlSafe::decode(Binary::safeSubstr($serialized, 9));
        $checksum = Binary::safeSubstr($decoded, 0, 16);
        $body = Binary::safeSubstr($decoded, 16);
        sodium_memzero($decoded);
        return [$header, $body, $checksum];
    }

    /**
     * @param string $serialized
     * @return AsymmetricPublicKey
     *
     * @throws CryptoException
     * @throws \SodiumException
     */
    protected function loadAsymmetricPublicKey(string $serialized): AsymmetricPublicKey
    {
        /**
         * @var string $header
         * @var string $body
         * @var string $checksum
         */
        [$header, $body, $checksum] = $this->getComponents($serialized);

        $calc = sodium_crypto_generichash($header . $body, '', 16);
        if (!hash_equals($calc, $checksum)) {
            throw new CryptoException("Checksum failed. Corrupt key?");
        }
        if (Binary::safeStrlen($body) < 64) {
            throw new CryptoException("Invalid key length.");
        }
        $pk = new AsymmetricPublicKey(
            new HiddenString(
                Binary::safeSubstr($body, 0, 32)
            )
        );
        $pk->injectBirationalEquivalent(
            new HiddenString(
                Binary::safeSubstr($body, 32, 32)
            )
        );
        sodium_memzero($body);
        return $pk;
    }

    /**
     * @param string $serialized
     * @return AsymmetricSecretKey
     *
     * @throws CryptoException
     * @throws \SodiumException
     */
    protected function loadAsymmetricSecretKey(string $serialized): AsymmetricSecretKey
    {
        /**
         * @var string $header
         * @var string $body
         * @var string $checksum
         */
        [$header, $body, $checksum] = $this->getComponents($serialized);

        $calc = sodium_crypto_generichash($header . $body, '', 16);
        if (!hash_equals($calc, $checksum)) {
            throw new CryptoException("Checksum failed. Corrupt key?");
        }
        if (Binary::safeStrlen($body) < 96) {
            throw new CryptoException("Invalid key length.");
        }
        $sk = new AsymmetricSecretKey(
            new HiddenString(
                Binary::safeSubstr($body, 0, 64)
            )
        );
        $sk->injectBirationalEquivalent(
            new HiddenString(
                Binary::safeSubstr($body, 64, 32)
            )
        );
        sodium_memzero($body);
        return $sk;
    }

    /**
     * @param string $serialized
     * @return SymmetricKey
     *
     * @throws CryptoException
     * @throws \SodiumException
     */
    protected function loadSymmetricKey(string $serialized): SymmetricKey
    {
        /**
         * @var string $header
         * @var string $body
         * @var string $checksum
         */
        [$header, $body, $checksum] = $this->getComponents($serialized);
        $calc = sodium_crypto_generichash($header . $body, '', 16);
        if (!hash_equals($calc, $checksum)) {
            throw new CryptoException("Checksum failed. Corrupt key?");
        }
        if (Binary::safeStrlen($body) < 32) {
            throw new CryptoException("Invalid key length.");
        }
        $key = new SymmetricKey(
            new HiddenString(
                Binary::safeSubstr($body, 0, 32)
            )
        );
        sodium_memzero($body);
        return $key;
    }

    /**
     * @param AsymmetricPublicKey $key
     * @return string
     * @throws \SodiumException
     */
    protected function saveAsymmetricPublicKey(AsymmetricPublicKey $key): string
    {
        /** @var string $header */
        $header = static::KTYPE_ASYMMETRIC_PUBLIC;
        $body = $key->getRawKeyMaterial() . $key->getBirationalPublic()->getString();
        $checksum = sodium_crypto_generichash($header . $body, '', 16);
        return $header . Base64UrlSafe::encode($checksum . $body);
    }

    /**
     * @param AsymmetricSecretKey $key
     * @return string
     * @throws \SodiumException
     */
    protected function saveAsymmetricSecretKey(AsymmetricSecretKey $key): string
    {
        /** @var string $header */
        $header = static::KTYPE_ASYMMETRIC_SECRET;
        $body = $key->getRawKeyMaterial() . $key->getBirationalSecret()->getString();
        $checksum = sodium_crypto_generichash($header . $body, '', 16);
        return $header . Base64UrlSafe::encode($checksum . $body);
    }

    /**
     * @param SymmetricKey $key
     * @return string
     * @throws \SodiumException
     */
    protected function saveSymmetricKey(SymmetricKey $key): string
    {
        /** @var string $header */
        $header = static::KTYPE_SYMMETRIC;
        $body = $key->getRawKeyMaterial();
        $checksum = sodium_crypto_generichash($header . $body, '', 16);
        return $header . Base64UrlSafe::encode($checksum . $body);
    }

    /**
     * @param string $unwrapped
     * @return string
     * @throws \SodiumException
     */
    protected function keyWrap(string $unwrapped): string
    {
        if (is_null($this->keywrapKey)) {
            return $unwrapped;
        }
        return Symmetric::encrypt(new HiddenString($unwrapped), $this->keywrapKey);
    }
}

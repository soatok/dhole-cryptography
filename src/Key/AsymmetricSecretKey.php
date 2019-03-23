<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto\Key;

use ParagonIE\HiddenString\HiddenString;
use Soatok\DholeCrypto\Contract\CryptographicKeyInterface;
use Soatok\DholeCrypto\KeyTrait;

/**
 * Class SymmetricKey
 * @package Soatok\DholeCrypto\Key
 */
final class AsymmetricSecretKey implements CryptographicKeyInterface
{
    use KeyTrait;

    /** @var HiddenString $secret */
    private $secret;

    /** @var HiddenString $birationalSecret */
    private $birationalSecret;

    /** @var AsymmetricPublicKey $public */
    private $public;

    /**
     * @return self
     * @throws \SodiumException
     */
    public static function generate(): self
    {
        $keypair = \sodium_crypto_sign_keypair();

        $sk = new HiddenString(
            \sodium_crypto_sign_secretkey($keypair)
        );
        $pk_hs = new HiddenString(
            \sodium_crypto_sign_publickey($keypair)
        );

        \sodium_memzero($keypair);
        $pk = new AsymmetricPublicKey($pk_hs);
        return new self($sk, $pk);
    }

    /**
     * AsymmetricSecretKey constructor.
     *
     * @param HiddenString $sk
     * @param AsymmetricPublicKey|null $pk
     * @throws \SodiumException
     */
    public function __construct(
        HiddenString $sk,
        ?AsymmetricPublicKey $pk = null
    ) {
        $this->secret = $sk;
        if (!$pk) {
            $rawSecret = $sk->getString();
            $pk_hs = new HiddenString(
                \sodium_crypto_sign_publickey_from_secretkey($rawSecret)
            );
            \sodium_memzero($rawSecret);
            $pk = new AsymmetricPublicKey($pk_hs);
        }
        $this->public = $pk;
    }

    /**
     * @return AsymmetricPublicKey
     */
    public function getPublicKey(): AsymmetricPublicKey
    {
        return $this->public;
    }

    /**
     * @return HiddenString
     */
    public function getHiddenString(): HiddenString
    {
        return $this->secret;
    }

    /**
     * Hazardous Material: Don't use this method recklessly.
     *
     * @return string
     */
    public function getRawKeyMaterial(): string
    {
        return $this->secret->getString();
    }

    /**
     * Get a birationally equivalent X25519 secret key
     *
     * @return HiddenString
     * @throws \SodiumException
     */
    public function getBirationalSecret(): HiddenString
    {
        if (!$this->birationalSecret) {
            $this->birationalSecret = new HiddenString(
                sodium_crypto_sign_ed25519_sk_to_curve25519(
                    $this->secret->getString()
                )
            );
        }
        return $this->birationalSecret;
    }
}

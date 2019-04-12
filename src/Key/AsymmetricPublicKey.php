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
final class AsymmetricPublicKey implements CryptographicKeyInterface
{
    use KeyTrait;

    /** @var HiddenString $public */
    private $public;

    /** @var HiddenString|null $birationalPublic */
    private $birationalPublic;

    /**
     * AsymmetricPublicKey constructor.
     *
     * @param HiddenString $pk
     */
    public function __construct(HiddenString $pk)
    {
        $this->public = $pk;
    }

    /**
     * @return HiddenString
     */
    public function getHiddenString(): HiddenString
    {
        return $this->public;
    }

    /**
     * Hazardous Material: Don't use this method recklessly.
     *
     * @return string
     */
    public function getRawKeyMaterial(): string
    {
        return $this->public->getString();
    }

    /**
     * Get a birationally equivalent X25519 public key
     *
     * @return HiddenString
     * @throws \SodiumException
     */
    public function getBirationalPublic(): HiddenString
    {
        if (empty($this->birationalPublic)) {
            $this->birationalPublic = new HiddenString(
                sodium_crypto_sign_ed25519_pk_to_curve25519(
                    $this->public->getString()
                )
            );
        }
        return $this->birationalPublic;
    }

    /**
     * Don't use this. It's meant to be used by the Keyring class.
     *
     * @param HiddenString $str
     * @return self
     *
     * @internal
     */
    public function injectBirationalEquivalent(HiddenString $str): self
    {
        $this->birationalPublic = $str;
        return $this;
    }
}

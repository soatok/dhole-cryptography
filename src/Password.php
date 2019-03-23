<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Exceptions\CryptoException;
use ParagonIE\HiddenString\HiddenString;

/**
 * Class Password
 * @package Soatok\DholeCrypto\Cryptography
 */
final class Password
{
    const DEFAULT = [
        'mem' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        'ops' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
    ];

    /** @var SymmetricKey $key */
    private $key;

    /** @var array<string, int> $options */
    private $options;

    /**
     * Password constructor.
     *
     * @param SymmetricKey $key
     * @param array $options
     */
    public function __construct(
        SymmetricKey $key,
        array $options = self::DEFAULT
    ) {
        $this->key = $key;
        $this->options = $options + self::DEFAULT;
    }

    /**
     * @param HiddenString $password
     * @param string $ad             Optional additional data
     *
     * @return string
     * @throws \SodiumException
     */
    public function hash(HiddenString $password, string $ad = ''): string
    {
        $hash = \sodium_crypto_pwhash_str(
            $password->getString(),
            $this->options['ops'],
            $this->options['mem']
        );
        $ciphertext = Symmetric::encryptWithAd(
            new HiddenString($hash),
            $this->key,
            $ad
        );
        \sodium_memzero($hash);
        return $ciphertext;
    }

    /**
     * @param HiddenString $password
     * @param string $encryptedHash
     * @param string $ad             Optional additional data
     *
     * @return bool
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function verify(
        HiddenString $password,
        string $encryptedHash,
        string $ad = ''
    ): bool {
        $hash = Symmetric::decryptWithAd($encryptedHash, $this->key, $ad);
        return \sodium_crypto_pwhash_str_verify(
            $hash->getString(),
            $password->getString()
        );
    }
}

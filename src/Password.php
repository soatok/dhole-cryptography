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
        'alg' => 'argon2id',
        'mem' => SODIUM_CRYPTO_PWHASH_MEMLIMIT_INTERACTIVE,
        'ops' => SODIUM_CRYPTO_PWHASH_OPSLIMIT_INTERACTIVE
    ];

    /** @var SymmetricKey $key */
    private $key;

    /** @var array<string, int|string> $options */
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
        /** @var array<string, int|string> $options */
        $options = $options + self::DEFAULT;
        $this->options = $options;
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
            (int) $this->options['ops'],
            (int) $this->options['mem']
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
     * @param string $encryptedHash
     * @param string $ad
     *
     * @return bool
     * @throws CryptoException
     * @throws \SodiumException
     */
    public function needsRehash(string $encryptedHash, string $ad = ''): bool
    {
        // Encode the current requirements string
        $encoded = 'm=' .
                       ((int) $this->options['mem'] >> 10) .
                   ',t=' .
                       $this->options['ops'] .
                   ',p=1';

        // Decrypt the hash
        $hash = Symmetric::decryptWithAd($encryptedHash, $this->key, $ad)->getString();

        // $argon2id$v=19$m=65536,t=2,p=1$salt$hash
        //  \######/      \#############/
        //   \####/        \###########/
        //    `--'          `---------'
        //      \                /
        //     This is all we need
        [$alg, , $params] = explode('$', ltrim($hash, '$'));
        sodium_memzero($hash);

        // Does the algorithm match what we expect?
        $current = hash_equals((string) $this->options['alg'], $alg);
        sodium_memzero($alg);

        // Do the parameters match the configured ops/mem costs?
        $current = $current && hash_equals($encoded, $params);
        sodium_memzero($params);
        sodium_memzero($encoded);

        // Return TRUE if not current (meaning: needs to be rehashed)s
        return !$current;
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

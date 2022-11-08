<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

use Soatok\DholeCrypto\Exceptions\FilesystemException;

/**
 * Class AsymmetricFile
 * @package Soatok\DholeCrypto
 */
class SymmetricFile
{
    const BUFFER_SIZE = 8192;

    /**
     * @param string|resource $file File to hash
     * @param string $preamble      Domain separation, etc.
     * @return string
     * @throws FilesystemException
     * @throws \SodiumException
     * @psalm-suppress RedundantConditionGivenDocblockType
     */
    public static function hash($file, string $preamble = ''): string
    {
        if (is_string($file)) {
            return self::hashFile($file, $preamble);
        }
        if (is_resource($file)) {
            return self::hashResource($file, $preamble);
        }
        throw new \TypeError('File must be a file path or file handle');
    }

    /**
     * @param string $fileName
     * @param string $preamble
     * @return string
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public static function hashFile(string $fileName, string $preamble = ''): string
    {
        $fp = fopen($fileName, 'rb');
        if (!is_resource($fp)) {
            throw new FilesystemException('Could not open file for reading: ' . $fileName);
        }
        try {
            return self::hashResource($fp, $preamble);
        } finally {
            @fclose($fp);
        }
    }

    /**
     * @param resource $fp
     * @param string $preamble
     * @return string
     * @throws FilesystemException
     * @throws \SodiumException
     */
    public static function hashResource($fp, string $preamble = ''): string
    {
        // Initialize
        $state = sodium_crypto_generichash_init('', 64);
        if ($preamble) {
            sodium_crypto_generichash_update($state, $preamble);
        }
        $start = ftell($fp);
        $stat = fstat($fp);
        $size = $stat['size'];
        fseek($fp, 0, SEEK_SET);
        $bytes = 0;
        while ($bytes < $size) {
            $toRead = min(self::BUFFER_SIZE, $size - $bytes);
            $buf = fread($fp, $toRead);
            if (!is_string($buf)) {
                throw new FilesystemException('Could not read input buffer');
            }
            sodium_crypto_generichash_update($state, $buf);
            $bytes += $toRead;
        }

        // Reset internal pointers
        fseek($fp, $start, SEEK_SET);
        return $preamble . sodium_crypto_generichash_final($state, 64);
    }
}

<?php
declare(strict_types=1);
namespace Soatok\DholeCrypto;

/**
 * Trait KeyTrait
 * @package Soatok\DholeCrypto
 */
trait KeyTrait
{
    /**
     * Never reveal its contents
     */
    public function __debugInfo()
    {
        return ['data' => 'Hidden.'];
    }
}

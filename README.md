# Dhole Cryptography

[![Build Status](https://github.com/soatok/dhole-cryptography/actions/workflows/ci.yml/badge.svg)](https://github.com/soatok/dhole-cryptography/actions)
[![Static Analysis](https://github.com/soatok/dhole-cryptography/actions/workflows/psalm.yml/badge.svg)](https://github.com/soatok/dhole-cryptography/actions)
[![Latest Stable Version](https://poser.pugx.org/soatok/dhole-cryptography/v/stable)](https://packagist.org/packages/soatok/dhole-cryptography)
[![Latest Unstable Version](https://poser.pugx.org/soatok/dhole-cryptography/v/unstable)](https://packagist.org/packages/soatok/dhole-cryptography)
[![License](https://poser.pugx.org/soatok/dhole-cryptography/license)](https://packagist.org/packages/soatok/dhole-cryptography)
[![Downloads](https://img.shields.io/packagist/dt/soatok/dhole-cryptography.svg)](https://packagist.org/packages/soatok/dhole-cryptography)

PHP libsodium wrapper for Soatok's PHP projects. Released under the very
permissive ISC license.

**Requires PHP 7.2**.

## Dhole Cryptography in Other Programming Languages

* [JavaScript (Node.js)](https://github.com/soatok/dholecrypto-js)

## Installing

```
composer require soatok/dhole-cryptography
```

## Usage

### Key Generation

You can generate a random key by invoking the static `generate()` method. This
is not permitted on `AsymmetricPublicKey` objects.

```php
<?php
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use Soatok\DholeCrypto\Key\SymmetricKey;

$secret = AsymmetricSecretKey::generate();
$symmetric = SymmetricKey::generate();
```

You can also instantiate key objects by passing a
[`HiddenString`](https://github.com/paragonie/hidden-string)
instance containing the key material to the constructor.

### Asymmetric Cryptography

#### Digital Signatures

```php
<?php
use Soatok\DholeCrypto\Asymmetric;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;

$secret = AsymmetricSecretKey::generate();
$public = $secret->getPublicKey();

$message = "I certify that you have paid your $350 awoo fine";
$sig = Asymmetric::sign($message, $secret);
if (!Asymmetric::verify($message, $public, $sig)) {
    die('AWOO FINE UNPAID');
}
```

#### Authenticated Public-Key Encryption

Note: You can only decrypt messages with this API. It combines 
`sodium_crypto_sign_detached()` with `sodium_crypto_box_seal()`
under the hood.

```php
<?php
use Soatok\DholeCrypto\Asymmetric;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use ParagonIE\HiddenString\HiddenString;

$aSecret = AsymmetricSecretKey::generate();
$aPublic = $aSecret->getPublicKey();
$bSecret = AsymmetricSecretKey::generate();
$bPublic = $bSecret->getPublicKey();

// Encryption
$message = new HiddenString(
    "This is a secret message for your ears only: UwU"
);
$encrypt = Asymmetric::encrypt($message, $bPublic, $aSecret);
$decrypt = Asymmetric::decrypt($encrypt, $bSecret, $aPublic);
```

#### Anonymous Public-Key Encryption

This is faster than the authenticated API (since it doesn't verify the sender's
Ed25519 signature), but anyone can encrypt messages to your public key.

```php
<?php
use Soatok\DholeCrypto\Asymmetric;
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use ParagonIE\HiddenString\HiddenString;

$secret = AsymmetricSecretKey::generate();
$public = $secret->getPublicKey();

// Encryption
$message = new HiddenString(
    "This is a secret message for your ears only: UwU"
);
$sealed = Asymmetric::seal($message, $public);

// Decryption
$unseal = Asymmetric::unseal($sealed, $secret);
```

### Symmetric-Key Cryptography

#### Encryption

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Symmetric;

$key = SymmetricKey::generate();

$message = new HiddenString('This is a secret, okay?');

$encrypted = Symmetric::encrypt($message, $key);
$decrypted = Symmetric::decrypt($encrypted, $key);
```

#### Encryption with Additional Data

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Symmetric;

$key = SymmetricKey::generate();

$message = new HiddenString('This is a secret, okay?');
$publicData = "OwO? UwU";

$encrypted = Symmetric::encryptWithAd($message, $key, $publicData);
$decrypted = Symmetric::decryptWithAd($encrypted, $key, $publicData);
```

#### Unencrypted Message Authentication

```php
<?php
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Symmetric;

$key = SymmetricKey::generate();

$msg = "This is a string";
$auth = Symmetric::auth($msg, $key);
if (!Symmetric::verify($msg, $key, $auth)) {
    die("access denied");
}
```

### Password Storage

```php
<?php
use ParagonIE\HiddenString\HiddenString;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Password;

$key = SymmetricKey::generate();

$pwHandler = new Password($key);

$password = new HiddenString('cowwect howse battewy staple UwU');
$pwhash = $pwHandler->hash($password);
if (!$pwHandler->verify($password, $pwhash)) {
    die("access denied");
}
```

### Keyring

You can serialize any key by using the `Keyring` class.

```php
<?php
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Keyring;

// Generate some keys...
$secretKey = AsymmetricSecretKey::generate();
$publicKey = $secretKey->getPublicKey();
$symKey = SymmetricKey::generate();

// Load a serializer.
$keyring = new Keyring();

// Serialize them as strings...
$sk = $keyring->save($secretKey);
$pk = $keyring->save($publicKey);
$key = $keyring->save($symKey);

// Load them from a string...
$loadSk = $keyring->load($sk);
$loadPk = $keyring->load($pk);
$loadKey = $keyring->load($key);
```

The `Keyring` class also supports keywrap. Simply pass a separate
`SymmetricKey` instance to the constructor to get wrapped keys.

```php
<?php
use Soatok\DholeCrypto\Key\AsymmetricSecretKey;
use Soatok\DholeCrypto\Key\SymmetricKey;
use Soatok\DholeCrypto\Keyring;

// Keywrap key...
$wrap = SymmetricKey::generate();

// Generate some keys...
$secretKey = AsymmetricSecretKey::generate();
$publicKey = $secretKey->getPublicKey();
$symKey = SymmetricKey::generate();

// Load a serializer.
$keyring = new Keyring($wrap);

// Serialize them as strings...
$sk = $keyring->save($secretKey);
$pk = $keyring->save($publicKey);
$key = $keyring->save($symKey);

// Load them from a string...
$loadSk = $keyring->load($sk);
$loadPk = $keyring->load($pk);
$loadKey = $keyring->load($key);
```

# Support

If you run into any trouble using this library, or something breaks,
feel free to file a Github issue.

If you need help with integration, [Soatok is available for freelance work](https://soatok.com/freelance).

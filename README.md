# Dhole Cryptography

PHP libsodium wrapper for Soatok's PHP projects. Released under the very
permissive ISC license.

**Requires PHP 7.2**.

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



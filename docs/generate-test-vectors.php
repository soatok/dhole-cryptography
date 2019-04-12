<?php
/*
GENERATE TEST VECTORS FOR DHOLE-CRYPTOGRAPHY
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░▒▒▒▒░▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░▒░░▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░▒░░▒▒▒▒▒▓▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒░░░░░░░░░▒░▒▒▓▓▒▒▓▓▓▒▓▓▓▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒░░░░▒░▒▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░▒░▒▒▒▓▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒░░▒▓▓▒▒░▒▒▒▒▒▒▓▓▒▒▓▓▒░▒░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░▒░▒▒▒▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒░▒▒▓▓▒▓▒▒▒▒▓▓▓▓█▓▒▒▒▒░░▒▒░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░▒▒░▒▒▓▓▓▓▓▓▓▓▓▓▒▒▒▓▒▒▒▒▒▒▓▒▓▒░░░▒▒▒▒▒▒▒▓▓▒▒▒▒░░░▒░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░▒░░▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▒▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▒▒▒▒░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░▒░░░▒▒▒▓▓▒▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒░░▒▒▒▒▒▓▓▓▓▒▒▓▓░░░░▒░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░░░▒░░░▒▓▒▓▒▒▒▒▒▒▓▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒░▒▒▒▒▒▒▒▒▓▒▓▒▒░░░▒▒▒░▒░░░░░░░░░░░░░░░░░░░░
░░░░░░▒▒░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▓▓▓▓▓▒▒▒▒▒▒▓▓██▓▒▒▒▒▒░░░░░▒▒▒░░░░░░░░░░░░░░░░░░░
░░░░░░░░▒░░░▒▒▒▒▒▒▒▒▒▒▓▒▓▓▓▒▒▓▓▓▓▓▓▓▓▓▒▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒░░░▒▒▒▓▒░░░░░░░░░░░░░░░░░
░░░░░░░░░▒░░░▒▒▒▒▒▒▒▓▒▒▓▒▓▓▓▓▓▒▓▒▒▒▓▓▓▓█▓▓▓▒▒██▓▓▒▒▒▒▒▒░░░░▒▒░░░░░░░░░░░░░░░░░░
░░░░░░░░░░▒░░▒░▒▒▒▒▒▒▓▓▒▒▒▓▒▓▓▓▓▓▓▓▓▓▓▓▓▓█▓▓▒▒▒▓▓▒▓▓▓▒▒░░░░▒░▒▒░░░░░░░░░░░░░░░░
░░░░░░░░░▒░░░░▒▒▒▒▒▒▓▓▒▓▓▓▒▓▒▓▓▓▓▓▓▒▒▒▓▒▒▓▓▓▓▓▒▒▒▓▓▓▒▒▒░░░░░▒▒░░░░░░░░░░░░░░░░░
░░░░░░░▒▒▒░░░░▒▒▒▒▒▒▒▒▒▓▒▓▓▓▒▒▒▒▓▒▓▓▓▓▓▒▒▒▒▒▒▒▒▒▓▒▒▒▒▒▒▒░░░░▒▒░░░░░░░░░░░░░░░░░
░░░░░░▒▒░░░░░▒░▒▒▒░▒▒▒▒▒▓▓▓▒▒▒▒▒▒▒▒▒▒▓▓▓▒▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░▒▒░░░░░░░░░░░░░░░
░░░░░░▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▒▓▒▒▒▒▒▒▒▓▒▒▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░▒▒▒▒▒░░░░░░░░░░░░░░
░░░░░░▒░░░▒░▒▒▒▒▒▒▒▒▒▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓▓▒▓▒▒▒▒▒▒▒▒▒▒▒░▒▒▒░░░▒▒░░░░░░░░░░░░░░░
░░░░░▒▒░░░▒▓▓▓▓▒▒▒▒▓▓▓▓▓▓██████▓▓▓▒▒▒▒▓▓▓▒▒▓▓▒▒▒▒▒▒▓▒▒▒▒▒▒░░░░░░░▒░░░░░░░░░░░░░
░░░░░▒▒░░░░▓▓▒▒▓▒▒▓▓▓▓▓██████▓▓▓▒▒▒▒▒▒▒▓▓▓▒▒▒▓▓▒▓▒▒▒▓▒▒▒▒▒░▒░░░▒▒▒▒▒░░░░░░░░░░░
░░░░░░▒▒░░▒▒▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▒▓▓▓▓▒▒▒▒▒▒▒▒▓▒▒▒▒▒▓▓▒▒▒▒▒▒▒▒▒▒░░░░░░░▒▒░░░░░░░░░░░░
░░░░░░▒▒▒▒▒░▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▓▓▒▒▓▒▒▒▒▒▒▒▓▒▒▒▓▓▒▒▒▒▒▒░▒░░░░▒▒░░░░░░░░░░░
░░░░░░░▒▒░▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▓▒▓▓▓▒▒▒▒▒▒▒▒▒▒▒░░░░▒░░░░░░░░░░░
░░░░░▒▒▒░▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▓▓▒▓▓▒▒▒▒▒▒▒░░░░░▒░░░░░░░░░░
░░░░░░▒░▒▒▒▒▓▓▓▒▓▓▓▓▓▓▓▓▓▓▓█▓▓▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒▓▒▒▒▓▓▓▓▓▓▒▒▒▒▒▒▒░░░░▒▒░░░░░░░░░
░░░░░░▒▒▒▒▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▒▒░░░░▒▒▒▒▒▒░░░▒▒▒▒▒▒▒▓▒▒▓▒▓▒▒▒▒▒▒▒▒▒▒░░░▒▒░░░░░░░░░
░░░▒░▓▓▓▓█████▒▒▒▒▓▓▓▓▓▓▓▓▒░░░░░░░▒░░▒▒▒▒░▒▒▒░▒▒▒▒▒▓▒▒▓▓▒▒▒▒▒▒▒▒▒░░░░▒░░░░░░░░░
░░░░▒▒███████▓▒▒░▒▒▓▒▒▓▒▓▒▒░░░▒▒░░░░▒░▒▒░░░░░▒▒▒▒▒▒▒▓▒▒▓▓▓▒▒▒▒▒░▒▒░░▒▒░░░░░░░░░
░░░░▒▒▓█████▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░░░▒▒▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░▒▒░░░░░░░░░
░░░░░▒░░▓█▓▓▓▓▒▒▒▒▒▒▒▒░▒▒▒▒▒▒▒▒▒▒▒▒░▒▒░▒░▒░▒░░░░░▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▒░░▒▒░░░░░░░░░
░░░░░░▒▒░░▒▓▓▓▓▓▓▓▓▓▓▓▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░▒▒░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒░░░░░░░░
░░░░░░▒▒░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒▒▒▒░░░░░░░▒░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒▒░░░░░░░
░░░░░░▒▒░░░░░░░░░░░▒▒▒▒░░▒▒▒▒▒▒▒▒▒░░░▒░▒▒▒▒░░▒▒░░░░▒░░░░▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒░░░░░░░
░░░░░░░▒░░░░░░░░░░░▒░░░░░░░░▒▒▒▒▒▒▒░▒▒▒░░░░░▒░░░░░░░░▒▒░▒▒▒▒▒▓▒▒▒▒▒▒▒▒▒▒▒▒░░░░░
░░░░░░▒▒░░░░░░░░░░░░░░░░░░▒▒▒▒▒▒▒▒▒▒▒▒▒▒░▒░░░░░░░░░░░▒▒▒▒▒▒▓▓▓▓▒▒▒▒▒▒▓▒▒▒▒▒▒░░░
░░░░░░▒▒▒░░░░░░░░░░░░░░░░░░░░░░░░▒▒▒░▒▒░░░░░░░░░░░▒▒░▒▒▒▒▒▒▒▓▓▓▒▒▒▒▓▓▒▓▒▒▒▒▒▒░░
░░░░░▒▒▒▒░░░░░░░░░░░░░░░░▒░░░░░░░░░▒▒▒░▒░░▒░░░░░▒░▒▒▒▒▒▒▒▓▓▓▓▓▓▒▒▓▒▓▓▓▒▓▒▒▒▒▒░░
░░░░░░░░▒▒▒░░░░░░░░░░░░░░░░░░░░░░▒▒░░▒░░░░░▒░░░░▒░▒▒▒▒▒▒▒▓▓▓▓▓▓▓▓▒▒▓▓▓▓▓▒▒▒▒▒▒░
*/
use ParagonIE\ConstantTime\Base64UrlSafe;
use Soatok\DholeCrypto\{
    Asymmetric,
    Keyring,
    Password,
    Symmetric
};
use Soatok\DholeCrypto\Key\{
    AsymmetricSecretKey,
    SymmetricKey
};
use ParagonIE\HiddenString\HiddenString;
require '../vendor/autoload.php';

$tests = [
    'version' => 'dhole100',
    'asymmetric' => [
        'participants' => [],
        'encrypt' => [],
        'seal' => [],
        'sign' => []
    ],
    'symmetric' => [
        'keys' => [],
        'auth' => [],
        'encrypt' => []
    ],
    'password' => [],
    'key-ring' => [
        'non-wrapped' => [],
        'wrapped' => []
    ]
];
try {
    $blake2bFox = sodium_crypto_generichash('red fox (vulpes vulpes)');
    $blake2bWolf = sodium_crypto_generichash('timber wolf (canis lupus)');
    $blake2bDhole = sodium_crypto_generichash('dhole (cuon alpinus)');
    $blake2bUwU = sodium_crypto_generichash('wrap my keys UwU');

    $symKeywrap = new SymmetricKey(new HiddenString($blake2bUwU));
    $symDhole = new SymmetricKey(new HiddenString($blake2bDhole));

    $foxKeypair = sodium_crypto_sign_seed_keypair($blake2bFox);
    $foxSecret = new AsymmetricSecretKey(
        new HiddenString(sodium_crypto_sign_secretkey($foxKeypair))
    );
    $foxPublic = $foxSecret->getPublicKey();

    $wolfKeypair = sodium_crypto_sign_seed_keypair($blake2bWolf);
    $wolfSecret = new AsymmetricSecretKey(
        new HiddenString(sodium_crypto_sign_secretkey($wolfKeypair))
    );
    $wolfPublic = $wolfSecret->getPublicKey();
    $tests['asymmetric']['participants'] = [
        'fox' => [
            'secret-key' => Base64UrlSafe::encode($foxSecret->getRawKeyMaterial()),
            'public-key' => Base64UrlSafe::encode($foxPublic->getRawKeyMaterial())
        ],
        'wolf' => [
            'secret-key' => Base64UrlSafe::encode($wolfSecret->getRawKeyMaterial()),
            'public-key' => Base64UrlSafe::encode($wolfPublic->getRawKeyMaterial())
        ]
    ];
    $tests['symmetric']['keys'] = [
        'default' => Base64UrlSafe::encode(
            $symDhole->getRawKeyMaterial()
        ),
        'fox-to-wolf' => Base64UrlSafe::encode(
            Asymmetric::keyExchange($foxSecret, $wolfPublic, true)
                ->getRawKeyMaterial()
        ),
        'wolf-to-fox' =>Base64UrlSafe::encode(
            Asymmetric::keyExchange($wolfSecret, $foxPublic, true)
                ->getRawKeyMaterial()
        ),
        'fox-from-wolf' => Base64UrlSafe::encode(
            Asymmetric::keyExchange($foxSecret, $wolfPublic, false)
                ->getRawKeyMaterial()
        ),
        'wolf-from-fox' => Base64UrlSafe::encode(
            Asymmetric::keyExchange($wolfSecret, $foxPublic, false)
                ->getRawKeyMaterial()
        ),
        'key-wrap' => Base64UrlSafe::encode(
            $symKeywrap->getRawKeyMaterial()
        )
    ];

    $messages = [
        new HiddenString(''),
        new HiddenString('this is a test message'),
        new HiddenString('trans rights are human rights'),

        // https://twitter.com/_Ninji/status/1116746819197915136
        new HiddenString("as a furry you are legally obligated to make cringey furry puns whenever pawsible\n\nthere is no excuse fur knot doing so\0\n")
    ];

    /** @var HiddenString $message */
    foreach ($messages as $message) {
        // Generate Asymmetric::encrypt() test vectors:
        $encrypted = Asymmetric::encrypt($message, $foxPublic, $wolfSecret);
        $decrypted = Asymmetric::decrypt($encrypted, $foxSecret, $wolfPublic);
        $tests['asymmetric']['encrypt'][] = [
            'sender' => 'wolf',
            'recipient' => 'fox',
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        $encrypted = Asymmetric::encrypt($message, $wolfPublic, $foxSecret);
        $decrypted = Asymmetric::decrypt($encrypted, $wolfSecret, $foxPublic);
        $tests['asymmetric']['encrypt'][] = [
            'sender' => 'fox',
            'recipient' => 'wolf',
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        $encrypted = Asymmetric::encrypt($message, $foxPublic, $foxSecret);
        $decrypted = Asymmetric::decrypt($encrypted, $foxSecret, $foxPublic);
        $tests['asymmetric']['encrypt'][] = [
            'sender' => 'fox',
            'recipient' => 'fox',
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        $encrypted = Asymmetric::encrypt($message, $wolfPublic, $wolfSecret);
        $decrypted = Asymmetric::decrypt($encrypted, $wolfSecret, $wolfPublic);
        $tests['asymmetric']['encrypt'][] = [
            'sender' => 'wolf',
            'recipient' => 'wolf',
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        // Generate Asymmetric::seal() test vectors:
        $sealed = Asymmetric::seal($message, $foxPublic);
        $unsealed = Asymmetric::unseal($sealed, $foxSecret);
        $tests['asymmetric']['seal'][] = [
            'recipient' => 'fox',
            'sealed' => $sealed,
            'unsealed' => $unsealed->getString()
        ];

        $sealed = Asymmetric::seal($message, $wolfPublic);
        $unsealed = Asymmetric::unseal($sealed, $wolfSecret);
        $tests['asymmetric']['seal'][] = [
            'recipient' => 'wolf',
            'sealed' => $sealed,
            'unsealed' => $unsealed->getString()
        ];

        // Generate Asymmetric::sign() test vectors:
        $sign = Asymmetric::sign($message->getString(), $foxSecret);
        $tests['asymmetric']['sign'][] = [
            'signer' => 'fox',
            'message' => $message->getString(),
            'signature' => $sign
        ];
        $sign = Asymmetric::sign($message->getString(), $foxSecret);
        $tests['asymmetric']['sign'][] = [
            'signer' => 'wolf',
            'message' => $message->getString(),
            'signature' => $sign
        ];

        $mac = Symmetric::auth($message->getString(), $symDhole);
        $tests['symmetric']['auth'][] = [
            'key' => 'default',
            'message' => $message->getString(),
            'mac' => $mac
        ];

        $encrypted = Symmetric::encrypt($message, $symDhole);
        $decrypted = Symmetric::decrypt($encrypted, $symDhole);
        $tests['symmetric']['encrypt'][] = [
            'key' => 'default',
            'aad' => '',
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        $aad = 'Bork whistle';
        $encrypted = Symmetric::encrypt($message, $symDhole, $aad);
        $decrypted = Symmetric::decrypt($encrypted, $symDhole, $aad);
        $tests['symmetric']['encrypt'][] = [
            'key' => 'default',
            'aad' => $aad,
            'encrypted' => $encrypted,
            'decrypted' => $decrypted->getString()
        ];

        $hasherA = new Password($symDhole);
        $hasherB = new Password($symDhole, ['mem' => 1 << 14, 'ops' => 3]);

        $pwhash = $hasherA->hash($message);
        $tests['password']['valid'][] = [
            'key' => 'default',
            'password' => $message->getString(),
            'aad' => '',
            'encrypted-pwhash' => $pwhash,
            'valid' => $hasherA->verify($message, $pwhash)
        ];
        $pwhash = $hasherA->hash($message, $aad);
        $tests['password']['valid'][] = [
            'key' => 'default',
            'password' => $message->getString(),
            'aad' => $aad,
            'encrypted-pwhash' => $pwhash,
            'valid' => $hasherA->verify($message, $pwhash, $aad)
        ];
    }
    $keyring0 = new Keyring();
    $keyring1 = new Keyring($symKeywrap);

    $tests['key-ring']['non-wrapped'] = [
        'fox-secret-key' => $keyring0->save($foxSecret),
        'fox-public-key' => $keyring0->save($foxPublic),
        'wolf-secret-key' => $keyring0->save($wolfSecret),
        'wolf-public-key' => $keyring0->save($wolfPublic),
        'symmetric-default' => $keyring0->save($symDhole)
    ];
    $tests['key-ring']['wrapped'] = [
        'fox-secret-key' => $keyring1->save($foxSecret),
        'fox-public-key' => $keyring1->save($foxPublic),
        'wolf-secret-key' => $keyring1->save($wolfSecret),
        'wolf-public-key' => $keyring1->save($wolfPublic),
        'symmetric-default' => $keyring1->save($symDhole)
    ];

} catch (Throwable $ex) {
    echo $ex->getMessage();
    exit(1);
}

file_put_contents('test-vectors.json', json_encode($tests, JSON_PRETTY_PRINT));

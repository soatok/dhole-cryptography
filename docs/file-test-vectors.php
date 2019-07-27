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
use Soatok\DholeCrypto\AsymmetricFile;
use Soatok\DholeCrypto\Key\{
    AsymmetricSecretKey
};
use Soatok\DholeCrypto\Keyring;
use ParagonIE\HiddenString\HiddenString;
require '../vendor/autoload.php';


$messages = [
    '',
    'this is a test message',
    'trans rights are human rights',

    // https://twitter.com/_Ninji/status/1116746819197915136
    "as a furry you are legally obligated to make cringey furry puns whenever pawsible\n\nthere is no excuse fur knot doing so\0\n"
];

$blake2bFox = sodium_crypto_generichash('red fox (vulpes vulpes)');
$foxKeypair = sodium_crypto_sign_seed_keypair($blake2bFox);
$foxSecret = new AsymmetricSecretKey(
    new HiddenString(sodium_crypto_sign_secretkey($foxKeypair))
);
$foxPublic = $foxSecret->getPublicKey();
$keyring = new Keyring();

$out = ['asymmetric-file-sign' => [
    'public-key' => $keyring->save($foxPublic),
    'tests' => []
]];
/** @var HiddenString $message */
foreach ($messages as $message) {
    $file = fopen('php://temp', 'wb');
    fwrite($file, $message);
    fseek($file, 0, SEEK_SET);
    $signature = AsymmetricFile::sign($file, $foxSecret);
    if (AsymmetricFile::verify($file, $foxPublic, $signature)) {
        $out['asymmetric-file-sign']['tests'][] = [
            'contents' => $message,
            'signature' => $signature,
        ];
    }
    fclose($file);
}
echo json_encode($out, JSON_PRETTY_PRINT);

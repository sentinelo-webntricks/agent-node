<?php
// Génère, avec l'implémentation PHP de référence (agent Composer), les fixtures que la
// suite Node déchiffre — et déchiffre celles que Node a produites. Lancé par
// `npm run fixtures:php` dans l'image composer:2, depuis la racine du monorepo :
//
//   docker run --rm -v "$PWD:/repo" -w /repo composer:2 \
//       php agents/node/tests/make-php-crypto-fixtures.php
//
// La preuve de compatibilité est croisée : un sens seul ne dit rien de l'autre.

declare(strict_types=1);

require __DIR__ . '/../../composer/vendor/autoload.php';

use Sentinelo\Agent\Adapter\OpenSslCrypto;
use Sentinelo\Agent\Platform\Environment;

putenv('SENTINELO_SECRET=fixture-secret-0123456789abcdef');
$crypto = new OpenSslCrypto(new Environment([]));
$dir = __DIR__ . '/fixtures';

// 1 Mio + 17 octets : un bloc plein et un partiel, pour exercer l'index dans les données authentifiées.
$plain = '';
for ($i = 0; strlen($plain) < 1048576 + 17; $i++) {
    $plain .= hash('sha256', (string) $i, true);
}
$plain = substr($plain, 0, 1048576 + 17);
file_put_contents($dir . '/php-plain.bin', $plain);
$crypto->encryptFile($dir . '/php-plain.bin', $dir . '/php-encrypted.bin.enc');
unlink($dir . '/php-plain.bin');
file_put_contents($dir . '/php-plain.sha256', hash('sha256', $plain));
file_put_contents($dir . '/php-string.txt', $crypto->encrypt('{"api_key":"clé-é-🙂"}'));

// Le sens inverse : ce que Node a chiffré, si la suite Node l'a déjà produit.
if (is_file($dir . '/node-encrypted.bin.enc')) {
    $crypto->decryptFile($dir . '/node-encrypted.bin.enc', $dir . '/node-decrypted-by-php.bin');
    echo 'node→php : ', hash_file('sha256', $dir . '/node-decrypted-by-php.bin'), "\n";
    unlink($dir . '/node-decrypted-by-php.bin');
    echo 'node→php string : ', $crypto->decrypt((string) file_get_contents($dir . '/node-string.txt')), "\n";
}
echo "fixtures PHP écrites\n";

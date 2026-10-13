<?php

declare(strict_types=1);

/**
 * Symmetric encryption of sensitive data at rest (Extra Mile 2).
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  Encryption vs. hashing vs. encoding vs. obfuscation
 * ───────────────────────────────────────────────────────────────────────────
 *  ENCRYPTION  (this class: openssl_encrypt, AES-256-CBC)
 *      Two-way and KEYED. Anyone with the secret key can turn the ciphertext
 *      back into the original; without the key it is unreadable.
 *      Use it for data the application must read again later: personal notes,
 *      API tokens of third-party services, IBANs, …
 *
 *  HASHING  (password_hash / password_verify, hash('sha256', …))
 *      ONE-WAY. There is no key and no way back; you can only hash a candidate
 *      again and compare. Passwords are hashed (Exercise 05), never encrypted:
 *      the app never needs the original, so it should not be able to recover
 *      it. Password hashes are deliberately slow and salted (bcrypt).
 *
 *  ENCODING  (base64, URL encoding, htmlspecialchars, JSON)
 *      Two-way and PUBLIC. No secret at all — it only changes the
 *      representation so data survives a transport or context (binary in text,
 *      "<" inside HTML). base64 is NOT protection: anyone can decode it.
 *
 *  OBFUSCATION  (minified JS, renamed variables, ROT13, "hidden" admin URLs)
 *      Makes something harder for humans to read, but relies on the method
 *      staying secret. Once the trick is known it offers no protection at all
 *      ("security through obscurity"). Never use it to protect data.
 *
 * ───────────────────────────────────────────────────────────────────────────
 *  Construction used here
 * ───────────────────────────────────────────────────────────────────────────
 *  - AES-256-CBC with a fresh random 16-byte IV for every message, so the same
 *    plaintext never produces the same ciphertext.
 *  - CBC alone only gives confidentiality: an attacker can flip bits in the
 *    ciphertext and change the decrypted text, and padding errors can leak
 *    the plaintext (padding-oracle attacks). Therefore the ciphertext is
 *    authenticated with HMAC-SHA256 (encrypt-then-MAC) and the MAC is checked
 *    with hash_equals() BEFORE anything is decrypted.
 *  - Separate sub-keys for encryption and authentication are derived from the
 *    master key with HKDF.
 *  - Stored format: "v1:" . base64( IV[16] | HMAC[32] | ciphertext )
 *    (the version prefix allows changing the algorithm/key later).
 *  (In new code an AEAD such as AES-256-GCM or sodium_crypto_secretbox would do
 *   all of this in one step; CBC is used because the exercise asks for it.)
 */
final class Crypto
{
    private const CIPHER = 'aes-256-cbc';
    private const VERSION = 'v1';
    private const IV_LENGTH = 16;
    private const MAC_LENGTH = 32;
    public const KEY_LENGTH = 32; // 256 bit

    private readonly string $encryptionKey;
    private readonly string $macKey;

    public function __construct(string $masterKey)
    {
        if (strlen($masterKey) !== self::KEY_LENGTH) {
            throw new InvalidArgumentException('The master key must be exactly 32 bytes.');
        }
        $this->encryptionKey = hash_hkdf('sha256', $masterKey, 32, 'aes-256-cbc encryption');
        $this->macKey = hash_hkdf('sha256', $masterKey, 32, 'hmac-sha256 authentication');
    }

    /**
     * The key comes from the APP_KEY environment variable (base64, production)
     * or from private/keys/app.key, which is generated on first use. It never
     * lives in the database, so a stolen database dump alone is useless.
     */
    public static function fromConfig(): self
    {
        $envKey = config('crypto.key');
        if (is_string($envKey) && $envKey !== '') {
            return new self(self::decodeKey($envKey, 'APP_KEY'));
        }

        $file = (string) config('crypto.key_file');
        if (!is_file($file)) {
            self::generateKeyFile($file);
        }

        return new self(self::decodeKey(trim((string) file_get_contents($file)), $file));
    }

    public function encrypt(string $plaintext): string
    {
        $iv = random_bytes(self::IV_LENGTH);
        $ciphertext = openssl_encrypt($plaintext, self::CIPHER, $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
        if ($ciphertext === false) {
            throw new RuntimeException('Encryption failed.');
        }

        $mac = hash_hmac('sha256', self::VERSION . $iv . $ciphertext, $this->macKey, true);

        return self::VERSION . ':' . base64_encode($iv . $mac . $ciphertext);
    }

    /**
     * @throws CryptoException when the data was tampered with or the key is wrong
     */
    public function decrypt(string $payload): string
    {
        [$version, $encoded] = array_pad(explode(':', $payload, 2), 2, '');
        $raw = base64_decode($encoded, true);

        if ($version !== self::VERSION || $raw === false || strlen($raw) <= self::IV_LENGTH + self::MAC_LENGTH) {
            throw new CryptoException('Malformed ciphertext.');
        }

        $iv = substr($raw, 0, self::IV_LENGTH);
        $mac = substr($raw, self::IV_LENGTH, self::MAC_LENGTH);
        $ciphertext = substr($raw, self::IV_LENGTH + self::MAC_LENGTH);

        // Authenticate first (constant-time comparison), decrypt only if intact.
        $expected = hash_hmac('sha256', self::VERSION . $iv . $ciphertext, $this->macKey, true);
        if (!hash_equals($expected, $mac)) {
            throw new CryptoException('Integrity check failed: the data was modified or the key is wrong.');
        }

        $plaintext = openssl_decrypt($ciphertext, self::CIPHER, $this->encryptionKey, OPENSSL_RAW_DATA, $iv);
        if ($plaintext === false) {
            throw new CryptoException('Decryption failed.');
        }

        return $plaintext;
    }

    public static function generateKey(): string
    {
        return base64_encode(random_bytes(self::KEY_LENGTH));
    }

    private static function generateKeyFile(string $file): void
    {
        $directory = dirname($file);
        if (!is_dir($directory)) {
            mkdir($directory, 0700, true);
        }

        // 'x' mode fails if another request created the file in the meantime.
        $handle = @fopen($file, 'x');
        if ($handle === false) {
            return;
        }
        fwrite($handle, self::generateKey() . PHP_EOL);
        fclose($handle);
        chmod($file, 0600); // readable by the PHP user only
    }

    private static function decodeKey(string $base64, string $source): string
    {
        $key = base64_decode($base64, true);
        if ($key === false || strlen($key) !== self::KEY_LENGTH) {
            throw new RuntimeException("Invalid encryption key in {$source}: expected 32 bytes, base64-encoded.");
        }

        return $key;
    }
}

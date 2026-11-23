package app.key;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

public final class KeyEncryptionKey implements Key {
    private final static SecureRandom secureRandom = new SecureRandom();

    private final byte[] key;
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    public KeyEncryptionKey() {
        key = generateKey();
    }
    public KeyEncryptionKey(byte[] existingKey) {
        if (existingKey.length != 32) throw new IllegalArgumentException("KEK must be 32 bytes long.");
        this.key = existingKey.clone();
    }

    private byte[] generateKey() {
        byte[] bytes = new byte[32];

        secureRandom.nextBytes(bytes);
        return bytes;
    }

    @Override
    public String getAlgorithm() {
        return "AES";
    }

    @Override
    public String getFormat() {
        return "RAW";
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof KeyEncryptionKey that)) return false;
        return Arrays.equals(key, that.key);
    }
    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
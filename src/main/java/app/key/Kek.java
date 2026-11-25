package app.key;

import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

public final class Kek implements Key {
    private final static SecureRandom secureRandom = new SecureRandom();

    private final byte[] key;
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    private final int version;
    public int getVersion() { return version; }

    public Kek(int version) {
        key = generateKey();
        this.version = version;
    }
    public Kek(byte[] existingKey, int version) {
        if (existingKey.length != 32) throw new IllegalArgumentException("KEK must be 32 bytes long.");
        this.key = existingKey.clone();
        this.version = version;
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
        if (!(o instanceof Kek that)) return false;
        return Arrays.equals(key, that.key);
    }
    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}
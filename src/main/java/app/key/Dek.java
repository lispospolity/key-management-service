package app.key;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

public class Dek implements Key {
    private final byte[] key;
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    public String toBase64() {
        return Base64.getEncoder()
                .withoutPadding()
                .encodeToString(key);
    }

    public Dek(byte[] key) {
        this.key = key.clone();
    }

    /**
     * @param base64Key
     * @throws IllegalArgumentException when the key is not 256bit (length is not 32 bytes)
     */
    public Dek(String base64Key) throws IllegalArgumentException {
        byte[] bytes = Base64.getDecoder()
                .decode(base64Key);
        if (bytes.length != 32) throw new IllegalArgumentException("Key must be 256bit");

        this.key = bytes;
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
        if (!(o instanceof Dek that)) return false;
        return Arrays.equals(key, that.key);
    }
    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}

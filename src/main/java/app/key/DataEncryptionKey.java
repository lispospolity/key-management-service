package app.key;

import java.security.Key;
import java.util.Arrays;
import java.util.Base64;

public class DataEncryptionKey implements Key {
    private final byte[] key;
    @Override
    public byte[] getEncoded() {
        return key.clone();
    }

    public String toBase64() {
        return Base64.getUrlEncoder()
                .withoutPadding()
                .encodeToString(key);
    }

    public DataEncryptionKey(String base64Dek) {
        key = Base64.getUrlDecoder()
                .decode(base64Dek);
    }
    public DataEncryptionKey(byte[] key) {
        this.key = key.clone();
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
        if (!(o instanceof DataEncryptionKey that)) return false;
        return Arrays.equals(key, that.key);
    }
    @Override
    public int hashCode() {
        return Arrays.hashCode(key);
    }
}

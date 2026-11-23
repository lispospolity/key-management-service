package app.key;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;

public class KeyTests {

    @Test
    void DEKRewrite() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        DataEncryptionKey key1 = new DataEncryptionKey(bytes);

        DataEncryptionKey key2 = new DataEncryptionKey(key1.toBase64());

        Assertions.assertEquals(key1, key2);
    }

    @Test
    void uniqueKEKs() {
        KeyEncryptionKey key1 = new KeyEncryptionKey();

        KeyEncryptionKey key2 = new KeyEncryptionKey();

        Assertions.assertNotEquals(key1, key2);
    }

    @Test
    void KEKRewrite() {
        KeyEncryptionKey key1 = new KeyEncryptionKey();

        KeyEncryptionKey key2 = new KeyEncryptionKey(key1.getEncoded());

        Assertions.assertEquals(key1, key2);
    }
}

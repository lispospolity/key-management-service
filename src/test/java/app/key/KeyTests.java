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

        Dek key1 = new Dek(bytes);

        Dek key2 = new Dek(key1.toBase64());

        Assertions.assertEquals(key1, key2);
    }

    @Test
    void uniqueKEKs() {
        Kek key1 = new Kek(0);

        Kek key2 = new Kek(0);

        Assertions.assertNotEquals(key1, key2);
    }

    @Test
    void KEKRewrite() {
        Kek key1 = new Kek(0);

        Kek key2 = new Kek(key1.getEncoded(), key1.getVersion());

        Assertions.assertEquals(key1, key2);
    }
}

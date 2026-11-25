package app.key;

import app.dto.Result;
import app.dto.response.ErrorResponse;
import app.key.dto.UnwrapKeyResponse;
import app.key.dto.WrapKeyResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;

public class KeyServiceTests {
    private Envelope wrapped1;
    private Dek unwrapped1;

    private Kek kek;

    private KeyService keyService;

    private Cipher wrapper;
    private Cipher unwrapper;
    @BeforeEach
    void setupKeys() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        kek = new Kek(0);

        keyService = new KeyService(kek);

        wrapper = Cipher.getInstance("AES/KWP/NoPadding");
        wrapper.init(Cipher.WRAP_MODE, kek);

        unwrapper = Cipher.getInstance("AES/KWP/NoPadding");
        unwrapper.init(Cipher.UNWRAP_MODE, kek);

        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256);

        SecretKey key1 = keyGenerator.generateKey();

        unwrapped1 = new Dek(key1.getEncoded());
        byte[] wrappedBytes = wrapper.wrap(key1);
        wrapped1 = new Envelope(Envelope.AES_ALGORITHM, kek.getVersion(), wrappedBytes);
    }

    @Test
    void wrap_success() {
        String id = UUID.randomUUID().toString();

        Result result = keyService.wrap(unwrapped1.toBase64(), id);

        WrapKeyResponse response = Assertions.assertInstanceOf(WrapKeyResponse.class, result.response());

        Envelope envelope = new Envelope(response.wrappedKeyBase64());

        Assertions.assertArrayEquals(wrapped1.getWrapped(), envelope.getWrapped());
    }

    @Test
    void wrap_nullInput() {
        String keyId = UUID.randomUUID().toString();
        Result result = keyService.wrap(null, keyId);

        Assertions.assertInstanceOf(ErrorResponse.class, result.response());
    }

    @Test
    void unwrap_success() {
        String keyId = UUID.randomUUID().toString();

        Result result = keyService.unwrap(wrapped1.toBase64(), keyId);

        UnwrapKeyResponse response = Assertions.assertInstanceOf(UnwrapKeyResponse.class, result.response());

        Dek unwrappedKey = new Dek(response.unwrappedKeyBase64());
        Assertions.assertArrayEquals(unwrapped1.getEncoded(), unwrappedKey.getEncoded());
    }

    @Test
    void unwrap_nullInput() {
        String keyId = UUID.randomUUID().toString();
        Result result = keyService.unwrap(null, keyId);

        Assertions.assertInstanceOf(ErrorResponse.class, result.response());
    }
}

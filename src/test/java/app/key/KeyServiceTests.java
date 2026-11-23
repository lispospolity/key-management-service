package app.key;

import app.dto.Result;
import app.dto.response.ErrorResponse;
import app.dto.response.Response;
import app.key.dto.UnwrapKeyResponse;
import app.key.dto.WrapKeyResponse;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class KeyServiceTests {
    private DataEncryptionKey wrapped;
    private DataEncryptionKey unwrapped;

    private KeyEncryptionKey kek;

    private KeyService keyService;

    private Cipher wrapper;
    private Cipher unwrapper;

    @BeforeEach
    void setupKeys() throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException {
        kek = new KeyEncryptionKey();

        keyService = new KeyService(kek);

        wrapper = Cipher.getInstance("AES/KWP/NoPadding");
        wrapper.init(Cipher.WRAP_MODE, kek);

        unwrapper = Cipher.getInstance("AES/KWP/NoPadding");
        unwrapper.init(Cipher.UNWRAP_MODE, kek);

        setupWrapped();
        setupUnwrapped();
    }
    void setupWrapped() throws IllegalBlockSizeException, InvalidKeyException {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        byte[] wrappedBytes = wrapper.wrap(new DataEncryptionKey(bytes));
        wrapped = new DataEncryptionKey(wrappedBytes);
    }
    void setupUnwrapped() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        unwrapped = new DataEncryptionKey(bytes);
    }

    @Test
    void wrap_success() throws IllegalBlockSizeException, InvalidKeyException {
        byte[] wrappedBytes = wrapper.wrap(unwrapped);
        DataEncryptionKey expectedKey = new DataEncryptionKey(wrappedBytes);

        Result result = keyService.wrap(unwrapped.toBase64());

        WrapKeyResponse response = Assertions.assertInstanceOf(WrapKeyResponse.class, result.response());

        Assertions.assertEquals(expectedKey.toBase64(), response.wrappedKeyBase64());
    }

    @Test
    void wrap_nullInput() {
        Result result = keyService.wrap(null);

        Assertions.assertInstanceOf(ErrorResponse.class, result.response());
    }

    @Test
    void unwrap_success() throws NoSuchAlgorithmException, InvalidKeyException {
        Key key = unwrapper.unwrap(wrapped.getEncoded(), wrapped.getAlgorithm(), Cipher.SECRET_KEY);
        DataEncryptionKey expectedKey = new DataEncryptionKey(key.getEncoded());

        Result result = keyService.unwrap(wrapped.toBase64());

        UnwrapKeyResponse response = Assertions.assertInstanceOf(UnwrapKeyResponse.class, result.response());

        Assertions.assertEquals(expectedKey.toBase64(), response.unwrappedKeyBase64());
    }

    @Test
    void unwrap_nullInput() {
        Result result = keyService.unwrap(null);

        Assertions.assertInstanceOf(ErrorResponse.class, result.response());
    }
}

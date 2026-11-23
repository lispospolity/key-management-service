package app.key;

import app.dto.Result;
import app.dto.response.ErrorResponse;
import app.dto.response.Response;
import app.key.dto.UnwrapKeyResponse;
import app.key.dto.WrapKeyResponse;
import app.logging.Debug;
import jakarta.validation.constraints.NotNull;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

@Service
public class KeyService {
    private final KeyEncryptionKey kek;

    public KeyService(@NotNull KeyEncryptionKey kek) {
        this.kek = kek;
    }

    public Result wrap(String base64UnwrappedDek) {
        if (base64UnwrappedDek == null || base64UnwrappedDek.isBlank()) {
            Response response = new ErrorResponse(
                    false,
                    "Provided key cannot be empty."
            );
            return new Result(401, response);
        }

        Cipher wrapper;
        try {
            wrapper = Cipher.getInstance("AES/KWP/NoPadding");
            wrapper.init(Cipher.WRAP_MODE, kek);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            return serverError(ex);
        }

        DataEncryptionKey unwrappedDek = new DataEncryptionKey(base64UnwrappedDek);

        try {
            byte[] wrapped = wrapper.wrap(unwrappedDek);

            DataEncryptionKey wrappedKey = new DataEncryptionKey(wrapped);

            Response response = new WrapKeyResponse(
                    true,
                    wrappedKey.toBase64(),
                    "Successfully wrapped key."
            );
            return new Result(200, response);

        } catch (IllegalBlockSizeException ex) {
            Response response = new ErrorResponse(
                    false,
                    "Provided key has an incorrect block size."
            );
            return new Result(401, response);
        } catch (InvalidKeyException ex) {
            Response response = new ErrorResponse(
                    false,
                    "Provided key is invalid."
            );
            return new Result(401, response);
        }
    }

    public Result unwrap(String base64WrappedDek) {
        if (base64WrappedDek == null || base64WrappedDek.isBlank()) {
            Response response = new ErrorResponse(
                    false,
                    "Provided key cannot be empty."
            );
            return new Result(401, response);
        }

        Cipher wrapper;
        try {
            wrapper = Cipher.getInstance("AES/KWP/NoPadding");
            wrapper.init(Cipher.UNWRAP_MODE, kek);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException ex) {
            return serverError(ex);
        }

        try {
            DataEncryptionKey wrappedKey = new DataEncryptionKey(base64WrappedDek);

            Key key = wrapper.unwrap(
                    wrappedKey.getEncoded(),
                    wrappedKey.getAlgorithm(),
                    Cipher.SECRET_KEY
            );
            DataEncryptionKey unwrappedKey = new DataEncryptionKey(key.getEncoded());

            Response response = new UnwrapKeyResponse(
                    true,
                    unwrappedKey.toBase64(),
                    "Successfully unwrapped key."
            );
            return new Result(200, response);

        } catch (InvalidKeyException ex) {
            Response response = new ErrorResponse(
                    false,
                    "Provided key is invalid."
            );
            return new Result(401, response);
        } catch (NoSuchAlgorithmException ex) { return serverError(ex); }
    }

    private Result serverError(Exception ex) {
        Debug.log("Exception in KeyService: " + ex);

        Response response = new ErrorResponse(
                false,
                "Internal Server Error"
        );
        return new Result(500, response);
    }
}

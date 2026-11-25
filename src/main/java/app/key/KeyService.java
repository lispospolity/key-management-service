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
    private final Kek kek;

    public KeyService(@NotNull Kek kek) {
        this.kek = kek;
    }

    public Result wrap(String base64PlainDek, String keyId) {
        if (base64PlainDek == null || base64PlainDek.isBlank()) {
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
        Dek dek;
        try {
            dek = new Dek(base64PlainDek);
        } catch (IllegalArgumentException ex) {
            Response response = new ErrorResponse(
                    false,
                    ex.getMessage()
            );
            return new Result(401, response);
        }

        try {
            byte[] wrapped = wrapper.wrap(dek);

            Envelope envelope = new Envelope(Envelope.AES_ALGORITHM, kek.getVersion(), wrapped);

            Response response = new WrapKeyResponse(
                    true,
                    keyId,
                    envelope.toBase64(),
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

    public Result unwrap(String base64Envelope, String keyId) {
        if (base64Envelope == null || base64Envelope.isBlank()) {
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

        Envelope envelope;
        try {
            envelope = new Envelope(base64Envelope);
        } catch (IllegalArgumentException ex) {
            Response response = new ErrorResponse(
                    false,
                    ex.getMessage()
            );
            return new Result(401, response);
        }

        try {
            Key key = wrapper.unwrap(
                    envelope.getWrapped(),
                    envelope.getAlgorithm(),
                    Cipher.SECRET_KEY
            );
            Dek unwrappedKey = new Dek(key.getEncoded());

            Response response = new UnwrapKeyResponse(
                    true,
                    keyId,
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

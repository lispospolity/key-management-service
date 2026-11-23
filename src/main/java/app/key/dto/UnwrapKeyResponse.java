package app.key.dto;

import app.dto.response.Response;

public record UnwrapKeyResponse(
        boolean success,
        String unwrappedKeyBase64,
        String message
) implements Response {
    @Override
    public boolean getSuccess() {
        return success;
    }
    @Override
    public String getMessage() {
        return message;
    }
}
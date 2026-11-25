package app.key;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

public class EnvelopeTests {
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private Kek kek;

    private byte[] byte0;
    private byte[] byte1;
    private byte[] byte40;
    private byte[] byte64;

    @BeforeEach
    void setupValues() {
        kek = new Kek(0);

        byte0 = new byte[0];

        byte1 = new byte[1];
        SECURE_RANDOM.nextBytes(byte1);

        byte40 = new byte[40];
        SECURE_RANDOM.nextBytes(byte40);

        byte64 = new byte[64];
        SECURE_RANDOM.nextBytes(byte64);
    }

    private String parseBase64(int format, int algorithm, int kekVersion, byte[] key) {
        ByteBuffer buffer = ByteBuffer.allocate(6+key.length);

        buffer.put((byte) format);

        buffer.put((byte) algorithm);

        buffer.putInt(kekVersion);

        buffer.put(key);

        byte[] bytes = buffer.array();

        return Base64.getEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

    @Test
    void envelope_wrongByteLength() {
        String byte0_base64 = parseBase64(0, Envelope.AES_ALGORITHM, kek.getVersion(), byte0);

        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new Envelope(byte0_base64));

        String byte1_base64 = parseBase64(0, Envelope.AES_ALGORITHM, kek.getVersion(), byte1);

        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new Envelope(byte1_base64));

        String byte64_base64 = parseBase64(0, Envelope.AES_ALGORITHM, kek.getVersion(), byte64);

        Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new Envelope(byte64_base64));
    }

    @Test
    void envelope_unsupportedVersion() {
        String base64 = parseBase64(-1, Envelope.AES_ALGORITHM, kek.getVersion(), byte40);

        IllegalArgumentException ex = Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new Envelope(base64));
        Assertions.assertEquals("Unsupported envelope version", ex.getMessage());
    }

    @Test
    void envelope_unsupportedAlgorithm() {
        String base64 = parseBase64(0, -1, kek.getVersion(), byte40);

        IllegalArgumentException ex = Assertions.assertThrows(
                IllegalArgumentException.class,
                () -> new Envelope(base64));
        Assertions.assertEquals("Algorithm not supported", ex.getMessage());
    }

    @Test
    void envelope_successValuesMatch() {
        int algorithm = Envelope.AES_ALGORITHM;
        int kekVersion = kek.getVersion();

        String byte40_base64 = parseBase64(0, algorithm, kekVersion, byte40);

        Envelope envelope = new Envelope(byte40_base64);

        Assertions.assertEquals("AES", envelope.getAlgorithm());
        Assertions.assertEquals(kekVersion, envelope.getKekVersion());
        Assertions.assertArrayEquals(byte40, envelope.getWrapped());
    }
}

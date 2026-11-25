package app.key;

import jakarta.annotation.Nullable;

import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.List;

/**
 * <pre>
 *     Envelope format version 0:
 *     Byte 0  -> format version
 *     Byte 1  -> algorithm in int
 *     2 to 6  -> which version of KEK was the key encrypted with
 *     7 to 46 -> the wrapped key
 * </pre>
 */
public class Envelope {
    public static final int AES_ALGORITHM = 0;
    private static final List<Integer> ALGORITHMS = List.of(AES_ALGORITHM);

    private int formatVersion;

    private int algorithm;
    public String getAlgorithm() {
        switch (algorithm) {
            case (AES_ALGORITHM) -> { return "AES"; }
            default -> { return "UNKNOWN"; }
        }
    }

    private int kekVersion;
    public int getKekVersion() {
        return kekVersion;
    }

    private byte[] wrappedKey;
    public byte[] getWrapped() {
        return wrappedKey.clone();
    }

    /**
     * @param base64Encoded takes in the wrapped envelope and parses it into the envelope object
     * @throws IllegalArgumentException when:<br>
     * a) the envelope length is 0<br>
     * b) the envelope length is not the same as version specified<br>
     * c) the algorithm is not supported<br>
     * d) the version is not supported
     */
    public Envelope(String base64Encoded) throws IllegalArgumentException {
        byte[] bytes = Base64.getDecoder()
                .decode(base64Encoded);

        extractData(bytes);
    }

    /**
     * This constructor does not have the necessary validation checks due to being only called with server-provided values (might need adjustments later)
     */
    public Envelope(int algorithm, int kekVersion, byte[] wrappedKey) {
        this.formatVersion = 0;
        this.algorithm = algorithm;
        this.kekVersion = kekVersion;
        this.wrappedKey = wrappedKey.clone();
    }

    private void extractData(byte[] bytes) {
        if (bytes.length == 0) throw new IllegalArgumentException("Envelope length cannot be 0");

        formatVersion = bytes[0];

        switch (formatVersion) {
            case (0) -> {
                if (bytes.length != 46) throw new IllegalArgumentException("Envelope length is not compliant with specified version");

                ByteBuffer buffer = ByteBuffer.wrap(bytes);

                formatVersion = Byte.toUnsignedInt(buffer.get());

                int alg = Byte.toUnsignedInt(buffer.get());
                if (!ALGORITHMS.contains(alg)) throw new IllegalArgumentException("Algorithm not supported");
                algorithm = alg;

                kekVersion = buffer.getInt();

                byte[] dekKey = new byte[40];
                buffer.get(dekKey);
                wrappedKey = dekKey;
            }
            default -> { throw new IllegalArgumentException("Unsupported envelope version"); }
        }
    }

    /**
     * @return either one of two:<br>
     * a) combined formatVersion, algorithm, kekVersion, wrappedKey formed into one base64 encoded string<br>
     * b) null when I really messed up the Envelope constructors and managed to get the formatVersion to be one that is not supported
     */
    public @Nullable String toBase64() {
        byte[] bytes;
        switch (formatVersion) {
            case(0) -> {
                ByteBuffer buffer = ByteBuffer.allocate(46);

                buffer.put((byte) 0);

                buffer.put((byte) algorithm);

                buffer.putInt(kekVersion);

                buffer.put(wrappedKey);

                bytes = buffer.array();
            }
            default -> { return null; }
        }
        return Base64.getEncoder()
                .withoutPadding()
                .encodeToString(bytes);
    }

}

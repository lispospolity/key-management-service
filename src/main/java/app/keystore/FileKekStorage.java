package app.keystore;

import app.config.AppConfig;
import app.key.Kek;
import jakarta.annotation.Nullable;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

@Component
public class FileKekStorage {
    private final Path keysDirectory;

    private final Pattern kekFilePattern;

    public FileKekStorage(AppConfig appConfig) {
        keysDirectory = appConfig.kekStoreDir;
        kekFilePattern = Pattern.compile("kek-v(\\d+)\\.bin");
    }

    /**
     * @return Map of KEKs indexed by their versions.
     *         Empty map if no matching key files are found.
     * @throws IOException if the directory or any matching key file cannot be read,
     *         or if a matching file has an invalid version.
     * @throws IllegalArgumentException if a key has an invalid length
     *         or a duplicate KEK version is found.
     */
    public Map<Integer, Kek> getAll() throws IOException, IllegalArgumentException {
        HashMap<Integer, Kek> keys = new HashMap<>();

        if (Files.notExists(keysDirectory)) return Map.of();

        if (!Files.isDirectory(keysDirectory)) throw new IOException("Provided path is not a directory.");

        try (Stream<Path> files = Files.list(keysDirectory)) {
            for (Path path : files.toList()) {
                Integer ver = getVersion(path);
                if (ver == null) continue;

                if (keys.putIfAbsent(ver, loadKekFromPath(path, ver)) != null) {
                    throw new IllegalArgumentException("Duplicate KEK version: " + ver);
                }
            }
        }

        return Map.copyOf(keys);
    }

    /**
     * @return version of the KEK by looking at the pattern in the path, or null when the pattern does not match
     */
    private @Nullable Integer getVersion(Path path) throws IOException {
        Matcher matcher = kekFilePattern.matcher(path.getFileName().toString());

        if (!matcher.matches()) return null;

        try {
            return Integer.parseInt(matcher.group(1));
        } catch (NumberFormatException ex) {
            throw new IOException(ex.getMessage());
        }
    }

    private Kek loadKekFromPath(Path path, Integer kekVersion) throws IOException, IllegalArgumentException {
        byte[] keyBytes = Files.readAllBytes(path);

        return new Kek(keyBytes, kekVersion);
    }

    public void saveKey(Kek key) throws IOException {
        Files.createDirectories(keysDirectory);

        Path path = keysDirectory.resolve("kek-v"+key.getVersion()+".bin");
        Files.write(
                path,
                key.getEncoded(),
                StandardOpenOption.CREATE_NEW,
                StandardOpenOption.WRITE
                );
    }
}
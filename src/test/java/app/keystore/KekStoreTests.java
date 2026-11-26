package app.keystore;

import app.config.AppConfig;
import app.config.Env;
import app.key.Kek;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;

public class KekStoreTests {
    private final Path nonexistentPath = Paths.get("src/test/resources/keystore/.env1");
    private final Path existingPath = Paths.get("src/test/resources/keystore/.env2");
    private final Path occupiedPath = Paths.get("src/test/resources/keystore/.env3");

    FileKekStorage createStorage(Path path) throws IOException {
        Env env = new Env(path, null);
        AppConfig appConfig = new AppConfig(env);

        return new FileKekStorage(appConfig);
    }

    @Test
    void nonexistentPath() throws IOException {
        FileKekStorage kekStorage = createStorage(nonexistentPath);

        Assertions.assertTrue(kekStorage.getAll().isEmpty());
    }

    @Test
    void nonexistentPath_save() throws IOException {
        FileKekStorage kekStorage = createStorage(nonexistentPath);

        kekStorage.saveKey(new Kek(0));

        Assertions.assertFalse(kekStorage.getAll().isEmpty());

        kekStorage.saveKey(new Kek(1));

        Map<Integer, Kek> keys = kekStorage.getAll();

        Assertions.assertNotNull(keys.get(0));
        Assertions.assertNotNull(keys.get(1));
    }

    @Test
    void existingPath() throws IOException {
        FileKekStorage kekStorage = createStorage(existingPath);
        Map<Integer, Kek> keys = kekStorage.getAll();

        Kek kek = keys.get(0);
        Assertions.assertNotNull(kek);

        Assertions.assertEquals(0, kek.getVersion());
    }

    @Test
    void existingPath_save() throws IOException {
        FileKekStorage kekStorage = createStorage(existingPath);

        kekStorage.saveKey(new Kek(1));

        Map<Integer, Kek> keys = kekStorage.getAll();

        Assertions.assertEquals(2, keys.size());

        Assertions.assertNotNull(keys.get(1));
    }

    @Test
    void occupiedPath() throws IOException {
        FileKekStorage kekStorage = createStorage(occupiedPath);
        Assertions.assertThrows(
                IOException.class,
                kekStorage::getAll);
    }

    @AfterEach
    void deleteKeys() throws IOException {
        deleteKeys1();
        clearKeys2();
    }
    void deleteKeys1() throws IOException {
        Path keys1 = Path.of("src/test/resources/keystore/keys1");

        if (!Files.isDirectory(keys1)) return;
        Path key0 = keys1.resolve("kek-v0.bin");
        Path key1 = keys1.resolve("kek-v1.bin");

        Files.deleteIfExists(key0);
        Files.deleteIfExists(key1);

        Files.delete(keys1);
    }
    void clearKeys2() throws IOException {
        Files.deleteIfExists(Path.of("src/test/resources/keystore/keys2/kek-v1.bin"));
    }
}

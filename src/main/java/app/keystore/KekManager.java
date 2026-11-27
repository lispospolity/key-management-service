package app.keystore;

import app.key.Kek;
import jakarta.annotation.Nullable;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@Component
public class KekManager {
    private final FileKekStorage kekStorage;

    private final Map<Integer, Kek> kekMap;

    private Integer latestVersion = -1;

    public KekManager(FileKekStorage kekStorage) throws IOException {
        this.kekStorage = kekStorage;

        this.kekMap = new HashMap<>(kekStorage.getAll());

        if (kekMap.isEmpty()) createNewKek();

        for (Integer ver : kekMap.keySet()) {
            if (ver>latestVersion) latestVersion = ver;
        }
    }

    public @Nullable Kek get(Integer version) {
        return kekMap.get(version);
    }

    public Kek getNewest() {
        return kekMap.get(latestVersion);
    }

    public Kek createNewKek() throws IOException {
        Kek newKek = new Kek(latestVersion + 1);

        kekStorage.saveKey(newKek);

        latestVersion++;
        kekMap.put(latestVersion, newKek);

        return newKek;
    }

}
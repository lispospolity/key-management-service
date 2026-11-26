package app.config;

import org.springframework.context.annotation.Configuration;

import java.nio.file.Path;

@Configuration
public class AppConfig {
    public Path kekStoreDir;

    public AppConfig(Env env) {
        kekStoreDir = Path.of(env.getRequired("KEK_STORE_DIR"));
    }
}

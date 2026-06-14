package client.config;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

public final class ApplicationConfig {

    private final Properties properties;

    public ApplicationConfig(Path path) throws IOException {
        properties = new Properties();

        try (InputStream in = Files.newInputStream(path)) {
            properties.load(in);
        }
        catch(Exception e)
        {
            System.out.println("Properties could not be loaded.");
            e.printStackTrace();
        }
    }

    public String mongoUri() {
        return properties.getProperty("mongo.uri");
    }

    public String mongoDatabase() {
        return properties.getProperty("mongo.database");
    }

    public String mongoCollection() {
        return properties.getProperty("mongo.collection");
    }

    public String employeesCsvPath()  {
        return properties.getProperty("employees.csv.path");
    }

    public String keysDirectory() {
        return properties.getProperty("keys.directory");
    }
}
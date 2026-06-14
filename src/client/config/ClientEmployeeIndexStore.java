package client.config;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

public final class ClientEmployeeIndexStore {

    private final Path file;
    private final Map<String, Entry> byEncryptedEmployeeId = new LinkedHashMap<>();

    public ClientEmployeeIndexStore(Path file) {
        this.file = Objects.requireNonNull(file, "file");
    }

    public static ClientEmployeeIndexStore loadOrCreate(Path file) throws IOException {
        ClientEmployeeIndexStore store = new ClientEmployeeIndexStore(file);
        if (Files.exists(file)) {
            store.load();
        } else {
            store.save();
        }
        return store;
    }

    public synchronized void clear() {
        byEncryptedEmployeeId.clear();
    }

    public synchronized void put(String encryptedEmployeeId, String employeeId, String fullName) {
        if (encryptedEmployeeId == null || encryptedEmployeeId.isBlank()) {
            return;
        }
        byEncryptedEmployeeId.put(
                encryptedEmployeeId,
                new Entry(
                        encryptedEmployeeId,
                        employeeId == null ? "" : employeeId,
                        fullName == null ? "" : fullName
                )
        );
    }

    public synchronized Optional<Entry> findByEncryptedEmployeeId(String encryptedEmployeeId) {
        return Optional.ofNullable(byEncryptedEmployeeId.get(encryptedEmployeeId));
    }

    public synchronized List<Entry> allEntries() {
        return new ArrayList<>(byEncryptedEmployeeId.values());
    }

    public synchronized int size() {
        return byEncryptedEmployeeId.size();
    }

    public synchronized void load() throws IOException {
        byEncryptedEmployeeId.clear();

        if (!Files.exists(file)) {
            return;
        }

        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.isBlank() || line.startsWith("#")) {
                    continue;
                }

                String[] parts = line.split("\t", -1);
                if (parts.length != 3) {
                    continue;
                }

                String encryptedEmployeeId = decode(parts[0]);
                String employeeId = decode(parts[1]);
                String fullName = decode(parts[2]);

                byEncryptedEmployeeId.put(
                        encryptedEmployeeId,
                        new Entry(encryptedEmployeeId, employeeId, fullName)
                );
            }
        }
    }

    public synchronized void save() throws IOException {
        Path parent = file.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }

        Path tmp = file.resolveSibling(file.getFileName().toString() + ".tmp");

        try (BufferedWriter writer = Files.newBufferedWriter(
                tmp,
                StandardCharsets.UTF_8
        )) {
            writer.write("# encryptedEmployeeId\temployeeId\tfullName");
            writer.newLine();

            for (Entry entry : byEncryptedEmployeeId.values()) {
                writer.write(encode(entry.getEncryptedEmployeeId()));
                writer.write('\t');
                writer.write(encode(entry.getEmployeeId()));
                writer.write('\t');
                writer.write(encode(entry.getFullName()));
                writer.newLine();
            }
        }

        try {
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static String encode(String value) {
        return Base64.getEncoder().encodeToString(
                (value == null ? "" : value).getBytes(StandardCharsets.UTF_8)
        );
    }

    private static String decode(String encoded) {
        return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
    }

    public static final class Entry {
        private final String encryptedEmployeeId;
        private final String employeeId;
        private final String fullName;

        public Entry(String encryptedEmployeeId, String employeeId, String fullName) {
            this.encryptedEmployeeId = encryptedEmployeeId;
            this.employeeId = employeeId;
            this.fullName = fullName;
        }

        public String getEncryptedEmployeeId() {
            return encryptedEmployeeId;
        }

        public String getEmployeeId() {
            return employeeId;
        }

        public String getFullName() {
            return fullName;
        }

        @Override
        public String toString() {
            return "Entry{" +
                    "encryptedEmployeeId='" + encryptedEmployeeId + '\'' +
                    ", employeeId='" + employeeId + '\'' +
                    ", fullName='" + fullName + '\'' +
                    '}';
        }
    }
}
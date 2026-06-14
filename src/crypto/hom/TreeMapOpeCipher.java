package crypto.hom;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.TreeMap;

public final class TreeMapOpeCipher implements OpeCipher {

    private static final long CIPHER_STEP = 1_000_000L;
    private final Path stateFile;
    private final TreeMap<Long, Long> plaintextToCipher;
    private final TreeMap<Long, Long> cipherToPlaintext;
    private long nextCipher;

    public static TreeMapOpeCipher loadOrCreate(Path stateFile) throws IOException {
        if (Files.exists(stateFile)) {
            return load(stateFile);
        }
        return new TreeMapOpeCipher(stateFile, new TreeMap<>(), new TreeMap<>(), CIPHER_STEP);
    }

    public static TreeMapOpeCipher load(Path stateFile) throws IOException {
        TreeMap<Long, Long> plainToCiph = new TreeMap<>();
        TreeMap<Long, Long> ciphToPlain = new TreeMap<>();
        long nextCipher = CIPHER_STEP;

        for (String rawLine : Files.readAllLines(stateFile, StandardCharsets.UTF_8)) {
            String line = rawLine.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }

            int eq = line.indexOf('=');
            if (eq < 0) {
                continue;
            }

            String key = line.substring(0, eq).trim();
            String value = line.substring(eq + 1).trim();

            if (key.equals("nextCipher")) {
                nextCipher = Long.parseLong(value);
            } else if (key.startsWith("map.")) {
                long plaintext = Long.parseLong(key.substring(4));
                long cipher = Long.parseLong(value);
                plainToCiph.put(plaintext, cipher);
                ciphToPlain.put(cipher, plaintext);
            }
        }

        long maxCipher = ciphToPlain.isEmpty() ? 0L : ciphToPlain.lastKey();
        long safeNextCipher = Math.max(nextCipher, maxCipher + CIPHER_STEP);

        return new TreeMapOpeCipher(stateFile, plainToCiph, ciphToPlain, safeNextCipher);
    }

    private TreeMapOpeCipher(
            Path stateFile,
            TreeMap<Long, Long> plainToCiph,
            TreeMap<Long, Long> ciphToPlain,
            long nextCipher) {

        this.stateFile = stateFile;
        this.plaintextToCipher = new TreeMap<>(plainToCiph);
        this.cipherToPlaintext = new TreeMap<>(ciphToPlain);

        long maxCipher = this.cipherToPlaintext.isEmpty() ? 0L : this.cipherToPlaintext.lastKey();
        this.nextCipher = Math.max(nextCipher, maxCipher + CIPHER_STEP);
    }

    @Override
    public synchronized long encrypt(long value) {
        Long existing = plaintextToCipher.get(value);
        if (existing != null) {
            return existing;
        }

        long cipher;
        if (plaintextToCipher.isEmpty()) {
            cipher = nextCipher;
            nextCipher += CIPHER_STEP;
        } else {
            Long lower = plaintextToCipher.lowerKey(value);
            Long higher = plaintextToCipher.higherKey(value);

            if (lower == null) {
                cipher = plaintextToCipher.get(higher) / 2L;
            } else if (higher == null) {
                cipher = plaintextToCipher.get(lower) + CIPHER_STEP;
            } else {
                long lowCipher = plaintextToCipher.get(lower);
                long highCipher = plaintextToCipher.get(higher);
                cipher = (lowCipher + highCipher) / 2L;

                if (cipher == lowCipher || cipher == highCipher) {
                    cipher = nextCipher;
                    nextCipher += CIPHER_STEP;
                }
            }
        }

        plaintextToCipher.put(value, cipher);
        cipherToPlaintext.put(cipher, value);
        persistQuietly();
        return cipher;
    }

    @Override
    public synchronized long decrypt(long token) {
        Long value = cipherToPlaintext.get(token);
        if (value == null) {
            throw new IllegalArgumentException("Unknown ciphertext: " + token);
        }
        return value;
    }

    public synchronized void save() throws IOException {
        if (stateFile.getParent() != null) {
            Files.createDirectories(stateFile.getParent());
        }

        StringBuilder sb = new StringBuilder();
        sb.append("nextCipher=").append(nextCipher).append('\n');
        for (Map.Entry<Long, Long> entry : plaintextToCipher.entrySet()) {
            sb.append("map.")
                    .append(entry.getKey())
                    .append('=')
                    .append(entry.getValue())
                    .append('\n');
        }

        Files.writeString(
                stateFile,
                sb.toString(),
                StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.CREATE,
                java.nio.file.StandardOpenOption.TRUNCATE_EXISTING,
                java.nio.file.StandardOpenOption.WRITE
        );
    }

    private void persistQuietly() {
        try {
            save();
        } catch (IOException e) {
            throw new IllegalStateException("Failed to persist OPE state to " + stateFile, e);
        }
    }
}
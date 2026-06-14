package client.service;

import client.config.ClientEmployeeIndexStore;
import crypto.EncryptionService;
import crypto.hom.OpeCipher;

import java.math.BigInteger;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

public final class RecordDecryptor {

    private final EncryptionService encryptionService;
    private final OpeCipher ageOpe;
    private final OpeCipher salaryOpe;
    private final ClientEmployeeIndexStore employeeIndexStore;

    public RecordDecryptor(
            EncryptionService encryptionService,
            OpeCipher ageOpe,
            OpeCipher salaryOpe,
            ClientEmployeeIndexStore employeeIndexStore
    ) {
        this.encryptionService = Objects.requireNonNull(encryptionService, "encryptionService");
        this.ageOpe = Objects.requireNonNull(ageOpe, "ageOpe");
        this.salaryOpe = Objects.requireNonNull(salaryOpe, "salaryOpe");
        this.employeeIndexStore = Objects.requireNonNull(employeeIndexStore, "employeeIndexStore");
    }

    public Map<String, Object> decrypt(Map<String, Object> encrypted) {
        Map<String, Object> result = new LinkedHashMap<>();

        for (Map.Entry<String, Object> entry : encrypted.entrySet()) {
            String key   = entry.getKey();
            Object value = entry.getValue();

            if (value == null) continue;

            if (key.endsWith("_rnd")) {
                String plainKey  = key.substring(0, key.length() - 4);
                String decrypted = encryptionService.decryptSensitiveText(String.valueOf(value));
                result.put(plainKey, decrypted);
                continue;
            }

            if (key.equals("age_ope")) {
                long plain = ageOpe.decrypt(toLong(value));
                result.put("age", plain);
                continue;
            }

            if (key.equals("salary_ope")) {
                long plainCents = salaryOpe.decrypt(toLong(value));
                result.put("salary", formatCentsAbs(plainCents));
                continue;
            }

            if (key.equals("salary_hom")) {
                BigInteger cipher = new BigInteger(String.valueOf(value));
                long cents = encryptionService.decryptSalaryCents(cipher);

                //result.put("salary_hom", value);
                result.put("salary_hom_plaintext", formatCentsAbs(cents));
                continue;
            }
        }

        Object encryptedEmployeeId = encrypted.get("employeeID_det");
        if (encryptedEmployeeId != null) {
            employeeIndexStore.findByEncryptedEmployeeId(String.valueOf(encryptedEmployeeId))
                    .ifPresent(entry -> {
                        result.put("employeeID", entry.getEmployeeId());
                        result.put("fullName", entry.getFullName());
                    });
        }
        return result;
    }

    private static long toLong(Object value) {
        if (value instanceof Number n) return n.longValue();
        return Long.parseLong(String.valueOf(value));
    }

    private static String formatCents(long cents) {
        long euros    = cents / 100L;
        long centPart = Math.abs(cents % 100L);
        return String.format("€%,d.%02d", euros, centPart);
    }

    private static String formatCentsToDollars(long cents) {
        long dollars  = cents / 100L;
        long centPart = Math.abs(cents % 100L);
        return String.format("$%,d.%02d", dollars, centPart);
    }

    public static String formatCentsAbs(long cents) {
        return formatCents(cents) + " | " +  formatCentsToDollars(cents);
    }
}
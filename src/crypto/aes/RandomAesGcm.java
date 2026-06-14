package crypto.aes;

import crypto.CryptoConfig;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

public final class RandomAesGcm {
    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public RandomAesGcm(SecretKey key) {
        this.key = key;
    }

    public static SecretKey generateKey() {
        try {
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg.generateKey();
        } catch (Exception e) {
            throw new RuntimeException("AES key generation failed", e);
        }
    }

    public String encrypt(String plaintext) {
        try {
            /**
            long start = System.nanoTime();
             */

            byte[] iv = new byte[CryptoConfig.AES_GCM_IV_SIZE];
            random.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);

            String base64 = Base64.getEncoder().encodeToString(out);

            /**
            long end = System.nanoTime();
            long ns = (end - start);
            System.out.println("[Execution time: " + ns + " ns]");
             */

            return base64;
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM encryption failed", e);
        }
    }

    public String decrypt(String ciphertextB64) {
        try {
            byte[] in = Base64.getDecoder().decode(ciphertextB64);
            byte[] iv = new byte[CryptoConfig.AES_GCM_IV_SIZE];
            byte[] ct = new byte[in.length - iv.length];

            System.arraycopy(in, 0, iv, 0, iv.length);
            System.arraycopy(in, iv.length, ct, 0, ct.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
            byte[] pt = cipher.doFinal(ct);

            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("AES-GCM decryption failed", e);
        }
    }
}
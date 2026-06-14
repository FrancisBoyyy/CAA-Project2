package crypto.aes;

import crypto.integrityandauthenticity.HmacUtil;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public final class DeterministicAesCtr {
    private final SecretKeySpec aesKey;
    private final byte[] ivKey;

    public DeterministicAesCtr(byte[] aesKeyBytes, byte[] ivKeyBytes) {
        if (aesKeyBytes.length != 32) {
            throw new IllegalArgumentException("AES-256 key must be 32 bytes");
        }
        this.aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        this.ivKey = ivKeyBytes.clone();
    }

    public String encrypt(String plaintext) {
        try {
            byte[] iv = deriveIv(plaintext);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] ct = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new RuntimeException("Deterministic AES-CTR encryption failed", e);
        }
    }

    public String decrypt(String ciphertextB64, String plaintextForIvDerivation) {
        try {
            byte[] iv = deriveIv(plaintextForIvDerivation);
            Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
            byte[] ct = Base64.getDecoder().decode(ciphertextB64);
            byte[] pt = cipher.doFinal(ct);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Deterministic AES-CTR decryption failed", e);
        }
    }

    private byte[] deriveIv(String plaintext) {
        byte[] mac = HmacUtil.hmacSha256(ivKey, plaintext);
        byte[] iv = new byte[16];
        System.arraycopy(mac, 0, iv, 0, 16);
        return iv;
    }
}
package crypto.integrityandauthenticity;

import java.nio.charset.StandardCharsets;
import java.security.*;

public final class SignatureUtil {
    private SignatureUtil() {}

    public static KeyPair generateEcdsaKeyPair() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            return kpg.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("ECDSA key generation failed", e);
        }
    }

    public static byte[] sign(PrivateKey privateKey, String message) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initSign(privateKey);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            return sig.sign();
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }

    public static boolean verify(PublicKey publicKey, String message, byte[] signatureBytes) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(publicKey);
            sig.update(message.getBytes(StandardCharsets.UTF_8));
            return sig.verify(signatureBytes);
        } catch (Exception e) {
            throw new RuntimeException("Verification failed", e);
        }
    }
}
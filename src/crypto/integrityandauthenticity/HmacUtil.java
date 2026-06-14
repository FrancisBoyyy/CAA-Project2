package crypto.integrityandauthenticity;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public final class HmacUtil {
    private HmacUtil() {}

    public static byte[] hmacSha256(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException("HMAC-SHA256 failed", e);
        }
    }

    public static byte[] hmacSha256(byte[] key, String text) {
        return hmacSha256(key, text.getBytes(StandardCharsets.UTF_8));
    }

    public static byte[] first16(byte[] input) {
        return Arrays.copyOf(input, 16);
    }
}
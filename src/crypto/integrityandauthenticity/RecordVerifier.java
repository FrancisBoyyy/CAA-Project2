package crypto.integrityandauthenticity;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public final class RecordVerifier {

    private final byte[]    hmacKey;
    private final PublicKey signingPublicKey;

    public RecordVerifier(byte[] hmacKey, PublicKey signingPublicKey) {
        this.hmacKey = Objects.requireNonNull(hmacKey).clone();
        this.signingPublicKey = Objects.requireNonNull(signingPublicKey);
    }

    public boolean verify(Map<String, Object> record) {
        String storedHmacB64 = field(record, "record_hmac");
        String storedSigB64 = field(record, "record_signature");

        if (storedHmacB64 == null || storedSigB64 == null) {
            return false;
        }

        String payload = canonicalPayload(record);

        byte[] expectedHmac = HmacUtil.hmacSha256(hmacKey, payload);
        String expectedHmacB64 = Base64.getEncoder().encodeToString(expectedHmac);

        if (!constantTimeEquals(expectedHmacB64, storedHmacB64)) {
            return false;
        }

        String signedMessage = payload + "|hmac=" + storedHmacB64;
        byte[] sigBytes = Base64.getDecoder().decode(storedSigB64);

        return SignatureUtil.verify(signingPublicKey, signedMessage, sigBytes);
    }

    public void verifyOrThrow(Map<String, Object> record) {
        if (!verify(record)) {
            throw new SecurityException(
                    "Record integrity/authenticity check FAILED. " +
                            "The record may have been tampered with by the server.");
        }
    }

    static String canonicalPayload(Map<String, Object> record) {
        List<String> keys = new ArrayList<>(record.keySet());
        Collections.sort(keys);

        StringBuilder sb = new StringBuilder();
        for (String key : keys) {
            if (key.equals("_id")
                    || key.equals("record_hmac")
                    || key.equals("record_signature")) {
                continue;
            }
            sb.append(key)
                    .append('=')
                    .append(Objects.toString(record.get(key), ""))
                    .append('\n');
        }
        return sb.toString();
    }

    private static String field(Map<String, Object> record, String name) {
        Object v = record.get(name);
        return v == null ? null : String.valueOf(v);
    }

    private static boolean constantTimeEquals(String a, String b) {
        if (a.length() != b.length()) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < a.length(); i++) {
            diff |= (a.charAt(i) ^ b.charAt(i));
        }
        return diff == 0;
    }
}
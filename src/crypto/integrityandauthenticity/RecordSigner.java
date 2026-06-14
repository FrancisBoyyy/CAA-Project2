package crypto.integrityandauthenticity;

import java.security.PrivateKey;
import java.util.*;

public final class RecordSigner {

    private final byte[] hmacKey;
    private final PrivateKey signingPrivateKey;

    public RecordSigner(byte[] hmacKey, PrivateKey signingPrivateKey) {
        this.hmacKey = Objects.requireNonNull(hmacKey).clone();
        this.signingPrivateKey = Objects.requireNonNull(signingPrivateKey);
    }

    public Map<String, Object> resign(Map<String, Object> record) {
        Map<String, Object> working = new LinkedHashMap<>(record);
        working.remove("record_hmac");
        working.remove("record_signature");

        String payload = canonicalPayload(working);

        byte[] hmacBytes = HmacUtil.hmacSha256(hmacKey, payload);
        String hmacB64 = Base64.getEncoder().encodeToString(hmacBytes);
        working.put("record_hmac", hmacB64);

        byte[] sigBytes = SignatureUtil.sign(signingPrivateKey, payload + "|hmac=" + hmacB64);
        working.put("record_signature", Base64.getEncoder().encodeToString(sigBytes));

        return working;
    }

    private static String canonicalPayload(Map<String, Object> record) {
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
}
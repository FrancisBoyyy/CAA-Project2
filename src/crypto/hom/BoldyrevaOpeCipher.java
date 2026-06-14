package crypto.hom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class BoldyrevaOpeCipher implements OpeCipher {

    private static final String HMAC_ALG = "HmacSHA256";

    private final byte[] key;
    private final long domainMax;
    private final long rangeMax;
    private final long bucketSize;

    public static BoldyrevaOpeCipher forAge(byte[] key) {
        return new BoldyrevaOpeCipher(key, 150L, 1L << 40);
    }

    public static BoldyrevaOpeCipher forSalaryCents(byte[] key) {
        return new BoldyrevaOpeCipher(key, 1_000_000_000L, Long.MAX_VALUE >>> 2);
    }

    public BoldyrevaOpeCipher(byte[] key, long domainMax, long rangeMax) {
        if (key == null || key.length < 16) {
            throw new IllegalArgumentException("Key must be at least 16 bytes");
        }
        if (domainMax < 0) {
            throw new IllegalArgumentException("domainMax must be non-negative");
        }
        if (rangeMax <= domainMax) {
            throw new IllegalArgumentException("rangeMax must be greater than domainMax");
        }

        this.key = Arrays.copyOf(key, key.length);
        this.domainMax = domainMax;
        this.rangeMax = rangeMax;

        long domainSize = domainMax + 1L;
        long rangeSize  = rangeMax + 1L;
        long bs = rangeSize / domainSize;

        if (bs <= 0L) {
            throw new IllegalArgumentException("Range is too small for the domain");
        }

        this.bucketSize = bs;
    }

    @Override
    public long encrypt(long value) {
        /**
        long start = System.nanoTime();
         */

        if (value < 0L || value > domainMax) {
            throw new IllegalArgumentException(
                    "Plaintext " + value + " outside domain [0, " + domainMax + ']');
        }

        long residue = Long.remainderUnsigned(prf(value), bucketSize);
        long res = Math.addExact(Math.multiplyExact(value, bucketSize), residue);

        /**
        long end = System.nanoTime();
        long ns = (end - start);
        System.out.println("[Execution time: " + ns + " ns]");
         */

        return res;
    }

    @Override
    public long decrypt(long token) {
        if (token < 0L || token > rangeMax) {
            throw new IllegalArgumentException(
                    "Ciphertext " + token + " outside range [0, " + rangeMax + ']');
        }

        long value = token / bucketSize;
        if (value < 0L || value > domainMax) {
            throw new IllegalArgumentException("Unknown OPE ciphertext token: " + token);
        }
        return value;
    }

    private long prf(long... ctx) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));

            ByteBuffer buf = ByteBuffer.allocate(ctx.length * Long.BYTES);
            for (long v : ctx) {
                buf.putLong(v);
            }

            byte[] digest = mac.doFinal(buf.array());
            return ByteBuffer.wrap(digest).getLong();
        } catch (Exception e) {
            throw new RuntimeException("BoldyrevaOpeCipher PRF (HMAC-SHA256) failed", e);
        }
    }
}
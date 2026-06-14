package crypto.hom;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.util.Arrays;

public final class BoldyrevaOpeCipher implements OpeCipher {

    private static final String HMAC_ALG = "HmacSHA256";

    private static final long EXACT_CDF_THRESHOLD = 2_000L;

    private final byte[] key;
    private final long domainMax;
    private final long rangeMax;

    public static BoldyrevaOpeCipher forAge(byte[] key) {
        return new BoldyrevaOpeCipher(key, 150L, 1L << 40);
    }

    public static BoldyrevaOpeCipher forSalaryCents(byte[] key) {
        return new BoldyrevaOpeCipher(key, 1_000_000_000L, Long.MAX_VALUE >>> 2);
    }

    public BoldyrevaOpeCipher(byte[] key, long domainMax, long rangeMax) {
        if (key == null || key.length < 16)
            throw new IllegalArgumentException("Key must be at least 16 bytes");
        if (domainMax <= 0)
            throw new IllegalArgumentException("domainMax must be positive");
        if (rangeMax <= domainMax)
            throw new IllegalArgumentException(
                    "rangeMax must be strictly greater than domainMax for meaningful spread");

        this.key       = Arrays.copyOf(key, key.length);
        this.domainMax = domainMax;
        this.rangeMax  = rangeMax;
    }

    @Override
    public long encrypt(long value) {
        if (value < 0 || value > domainMax)
            throw new IllegalArgumentException(
                    "Plaintext " + value + " outside domain [0, " + domainMax + ']');
        return traverse(value, 0L, domainMax, 0L, rangeMax);
    }

    @Override
    public long decrypt(long token) {
        long lo = 0L, hi = domainMax;
        while (lo <= hi) {
            long mid = lo + (hi - lo) / 2L;
            long enc = traverse(mid, 0L, domainMax, 0L, rangeMax);
            if      (enc == token) return mid;
            else if (enc <  token) lo = mid + 1L;
            else                   hi = mid - 1L;
        }
        throw new IllegalArgumentException("Unknown OPE ciphertext token: " + token);
    }

    private long traverse(long x, long dLo, long dHi, long rLo, long rHi) {
        long dSpan = dHi - dLo;
        long rSpan = rHi - rLo;

        if (dSpan == 0L) {
            long coins = prf(dLo, rLo, rHi);
            return rLo + Long.remainderUnsigned(coins, rSpan + 1L);
        }

        long dMid   = dLo + dSpan / 2L;
        long leftD  = dMid - dLo + 1L;
        long totalD = dSpan + 1L;
        long totalR = rSpan + 1L;

        long leftR = sampleHGD(totalR, leftD, totalD, dLo, dHi, rLo, rHi);

        long rightD = totalD - leftD;
        leftR = Math.max(leftD, Math.min(totalR - rightD, leftR));

        long rMid = rLo + leftR - 1L;

        return (x <= dMid)
                ? traverse(x, dLo,    dMid, rLo,    rMid)
                : traverse(x, dMid+1, dHi,  rMid+1, rHi);
    }

    private long sampleHGD(long N, long K, long n,
                           long dLo, long dHi, long rLo, long rHi) {
        long lo = Math.max(0L, n + K - N);
        long hi = Math.min(n, K);
        if (lo == hi) return lo;

        long span = hi - lo + 1L;

        long raw = prf(dLo, dHi, rLo, rHi, N, K, n);
        double u = (raw & 0x001F_FFFF_FFFF_FFFFL) / (double)(1L << 53);

        if (span > EXACT_CDF_THRESHOLD) {
            return lo + (long)(u * span);
        }

        double logPk = logHGDPmf(lo, N, K, n);
        double cdf   = Math.exp(logPk);

        for (long k = lo; k < hi; k++) {
            if (u <= cdf) return k;

            double num = (double)(K - k) * (double)(n - k);
            double den = (double)(k + 1L) * (double)(N - K - n + k + 1L);
            if (den <= 0.0) break;
            logPk += Math.log(num / den);
            cdf   += Math.exp(logPk);
        }
        return hi;
    }

    private static double logHGDPmf(long k, long N, long K, long n) {
        return logBinom(K, k) + logBinom(N - K, n - k) - logBinom(N, n);
    }

    private static double logBinom(long n, long k) {
        if (k < 0L || k > n) return Double.NEGATIVE_INFINITY;
        if (k == 0L || k == n) return 0.0;
        return logGamma(n + 1L) - logGamma(k + 1L) - logGamma(n - k + 1L);
    }

    private static double logGamma(long x) {
        return switch ((int) Math.min(x, 5L)) {
            case 0, 1 -> 0.0;
            case 2 -> 0.0;
            case 3 -> Math.log(2.0);
            case 4 -> Math.log(6.0);
            default -> {
                double n = (double) x;
                yield (n - 0.5) * Math.log(n)
                        - n
                        + 0.5 * Math.log(2.0 * Math.PI)
                        + 1.0 / (12.0 * n)
                        - 1.0 / (360.0 * n * n * n);
            }
        };
    }

    private long prf(long... ctx) {
        try {
            Mac mac = Mac.getInstance(HMAC_ALG);
            mac.init(new SecretKeySpec(key, HMAC_ALG));

            ByteBuffer buf = ByteBuffer.allocate(ctx.length * Long.BYTES);
            for (long v : ctx) buf.putLong(v);
            byte[] digest = mac.doFinal(buf.array());

            return ByteBuffer.wrap(digest).getLong();
        } catch (Exception e) {
            throw new RuntimeException("BoldyrevaOpeCipher PRF (HMAC-SHA256) failed", e);
        }
    }
}
package crypto;

public final class CryptoConfig {
    private CryptoConfig() {}

    public static final int AES_256_KEY_SIZE = 32;
    public static final int AES_GCM_IV_SIZE = 12;
    public static final int AES_CTR_IV_SIZE = 16;

    public static final int SHA256_BYTES = 32;
    public static final int HMAC_SHA256_BYTES = 32;

    public static final int PAILLIER_KEY_BITS = 2048;
}
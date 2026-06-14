package crypto.hom;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Paillier Cryptosystem Implementation
 *
 * Supports:
 *  - Key generation (2048-bit)
 *  - Encryption / Decryption
 *  - Homomorphic addition of ciphertexts
 *  - Homomorphic addition of a plaintext constant to a ciphertext
 *  - Homomorphic multiplication of a ciphertext by a plaintext scalar
 *
 * Reference: Pascal Paillier, "Public-Key Cryptosystems Based on Composite
 * Degree Residuosity Classes", EUROCRYPT 1999.
 */
public class PaillierCryptosystem {

    // -------------------------------------------------------------------------
    // Key classes
    // -------------------------------------------------------------------------

    public static class PublicKey {
        public final BigInteger n;       // n = p * q
        public final BigInteger g;       // g = n + 1  (simplified generator)
        public final BigInteger nSquared; // n^2, precomputed for efficiency

        public PublicKey(BigInteger n, BigInteger g) {
            this.n        = n;
            this.g        = g;
            this.nSquared = n.multiply(n);
        }

        @Override
        public String toString() {
            return "PublicKey{\n  n (hex) = " + n.toString(16) + "\n}";
        }
    }

    public static class PrivateKey {
        public final BigInteger lambda;  // lcm(p-1, q-1)
        public final BigInteger mu;      // modular inverse of L(g^lambda mod n^2) mod n
        public final PublicKey publicKey;

        public PrivateKey(BigInteger lambda, BigInteger mu, PublicKey publicKey) {
            this.lambda    = lambda;
            this.mu        = mu;
            this.publicKey = publicKey;
        }
    }

    public static class KeyPair {
        public final PublicKey  publicKey;
        public final PrivateKey privateKey;

        public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
            this.publicKey  = publicKey;
            this.privateKey = privateKey;
        }
    }

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    /**
     * Generates a Paillier key pair.
     *
     * @param bitLength Total bit-length of n (e.g. 2048). p and q are each
     *                  bitLength/2 bits.
     * @return A fresh {@link KeyPair}.
     */
    public static KeyPair generateKeyPair(int bitLength) {
        SecureRandom rng = new SecureRandom();

        BigInteger p, q, n;
        // Ensure p != q and gcd(p*q, (p-1)*(q-1)) == 1
        do {
            p = BigInteger.probablePrime(bitLength / 2, rng);
            q = BigInteger.probablePrime(bitLength / 2, rng);
            n = p.multiply(q);
        } while (p.equals(q) ||
                 !n.gcd(p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)))
                   .equals(BigInteger.ONE));

        BigInteger nSquared = n.multiply(n);

        // Simplified generator: g = n + 1
        // This choice always satisfies the Paillier requirements and avoids
        // the general (expensive) generator search.
        BigInteger g = n.add(BigInteger.ONE);

        // lambda = lcm(p-1, q-1)
        BigInteger pMinus1 = p.subtract(BigInteger.ONE);
        BigInteger qMinus1 = q.subtract(BigInteger.ONE);
        BigInteger lambda  = lcm(pMinus1, qMinus1);

        // mu = (L(g^lambda mod n^2))^-1 mod n
        // With g = n+1 this simplifies to lambda^-1 mod n.
        BigInteger mu = lambda.modInverse(n);

        PublicKey  pub  = new PublicKey(n, g);
        PrivateKey priv = new PrivateKey(lambda, mu, pub);

        return new KeyPair(pub, priv);
    }

    // -------------------------------------------------------------------------
    // Encryption
    // -------------------------------------------------------------------------

    /**
     * Encrypts a plaintext value m.
     *
     * @param m         Plaintext in [0, n).
     * @param publicKey The recipient's public key.
     * @return Ciphertext c in Z_{n^2}*.
     */
    public static BigInteger encrypt(BigInteger m, PublicKey publicKey) {
        if (m.signum() < 0 || m.compareTo(publicKey.n) >= 0) {
            throw new IllegalArgumentException(
                "Plaintext m must be in [0, n). Got: " + m);
        }

        SecureRandom rng = new SecureRandom();
        BigInteger r;
        // r must be in Z_n* (i.e. gcd(r, n) == 1)
        do {
            r = new BigInteger(publicKey.n.bitLength(), rng);
        } while (r.compareTo(BigInteger.ONE) < 0 ||
                 r.compareTo(publicKey.n) >= 0 ||
                 !r.gcd(publicKey.n).equals(BigInteger.ONE));

        // c = g^m * r^n mod n^2
        BigInteger gm = publicKey.g.modPow(m, publicKey.nSquared);
        BigInteger rn = r.modPow(publicKey.n, publicKey.nSquared);

        return gm.multiply(rn).mod(publicKey.nSquared);
    }

    /**
     * Convenience overload for long plaintexts.
     */
    public static BigInteger encrypt(long m, PublicKey publicKey) {
        return encrypt(BigInteger.valueOf(m), publicKey);
    }

    // -------------------------------------------------------------------------
    // Decryption
    // -------------------------------------------------------------------------

    /**
     * Decrypts a ciphertext.
     *
     * @param c          Ciphertext produced by {@link #encrypt}.
     * @param privateKey The corresponding private key.
     * @return Plaintext m in [0, n).
     */
    public static BigInteger decrypt(BigInteger c, PrivateKey privateKey) {
        PublicKey pub = privateKey.publicKey;

        // m = L(c^lambda mod n^2) * mu mod n
        BigInteger cLambda = c.modPow(privateKey.lambda, pub.nSquared);
        BigInteger lValue  = lFunction(cLambda, pub.n);

        return lValue.multiply(privateKey.mu).mod(pub.n);
    }

    // -------------------------------------------------------------------------
    // Homomorphic operations
    // -------------------------------------------------------------------------

    /**
     * Homomorphic addition of two ciphertexts.
     * D(addCiphertexts(E(m1), E(m2))) == (m1 + m2) mod n
     *
     * @param c1        Encryption of m1.
     * @param c2        Encryption of m2.
     * @param publicKey Public key used to encrypt m1 and m2.
     * @return Encryption of (m1 + m2) mod n.
     */
    public static BigInteger addCiphertexts(BigInteger c1, BigInteger c2,
                                            PublicKey publicKey) {
        return c1.multiply(c2).mod(publicKey.nSquared);
    }

    /**
     * Homomorphic addition of a plaintext constant to a ciphertext.
     * D(addPlaintext(E(m), k)) == (m + k) mod n
     *
     * @param c         Encryption of m.
     * @param k         Plaintext constant k in [0, n).
     * @param publicKey Public key used to encrypt m.
     * @return Encryption of (m + k) mod n.
     */
    public static BigInteger addPlaintext(BigInteger c, BigInteger k,
                                          PublicKey publicKey) {
        // E(k) with r=1: g^k mod n^2  (no randomness — only use for the
        // scalar addend, never as a standalone ciphertext)
        BigInteger gk = publicKey.g.modPow(k, publicKey.nSquared);
        return c.multiply(gk).mod(publicKey.nSquared);
    }

    /**
     * Homomorphic scalar multiplication (multiply plaintext by a constant).
     * D(multiplyByScalar(E(m), k)) == (m * k) mod n
     *
     * @param c         Encryption of m.
     * @param k         Plaintext scalar k in [0, n).
     * @param publicKey Public key used to encrypt m.
     * @return Encryption of (m * k) mod n.
     */
    public static BigInteger multiplyByScalar(BigInteger c, BigInteger k,
                                              PublicKey publicKey) {
        return c.modPow(k, publicKey.nSquared);
    }

    /**
     * Convenience overload for long scalars.
     */
    public static BigInteger multiplyByScalar(BigInteger c, long k,
                                              PublicKey publicKey) {
        return multiplyByScalar(c, BigInteger.valueOf(k), publicKey);
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /** L(x) = (x - 1) / n */
    private static BigInteger lFunction(BigInteger x, BigInteger n) {
        return x.subtract(BigInteger.ONE).divide(n);
    }

    /** lcm(a, b) = |a * b| / gcd(a, b) */
    private static BigInteger lcm(BigInteger a, BigInteger b) {
        return a.multiply(b).abs().divide(a.gcd(b));
    }
}

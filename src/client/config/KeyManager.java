package client.config;

import crypto.hom.PaillierCryptosystem;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Properties;

public final class KeyManager {

    private final Path keyDirectory;

    public KeyManager(Path keyDirectory) throws IOException {
        this.keyDirectory = keyDirectory;
        Files.createDirectories(keyDirectory);
    }

    public byte[] loadOrCreateBytes(String fileName, int size) throws IOException {
        Path file = keyDirectory.resolve(fileName);
        if (Files.exists(file)) {
            return Base64.getDecoder().decode(Files.readString(file).trim());
        }
        byte[] value = new byte[size];
        new SecureRandom().nextBytes(value);
        Files.writeString(file, Base64.getEncoder().encodeToString(value));
        return value;
    }

    public SecretKey loadOrCreateAesKey(String fileName) throws Exception {
        Path file = keyDirectory.resolve(fileName);
        if (Files.exists(file)) {
            byte[] encoded = Base64.getDecoder().decode(Files.readString(file).trim());
            return new SecretKeySpec(encoded, "AES");
        }
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        SecretKey key = generator.generateKey();
        Files.writeString(file, Base64.getEncoder().encodeToString(key.getEncoded()));
        return key;
    }

    public KeyPair loadOrCreateEcdsaKeyPair(String privateKeyFile, String publicKeyFile)
            throws Exception {
        Path privFile = keyDirectory.resolve(privateKeyFile);
        Path pubFile  = keyDirectory.resolve(publicKeyFile);

        if (Files.exists(privFile) && Files.exists(pubFile)) {
            byte[] privBytes = Base64.getDecoder().decode(Files.readString(privFile).trim());
            byte[] pubBytes  = Base64.getDecoder().decode(Files.readString(pubFile).trim());
            KeyFactory kf    = KeyFactory.getInstance("EC");
            PrivateKey priv  = kf.generatePrivate(new PKCS8EncodedKeySpec(privBytes));
            PublicKey  pub   = kf.generatePublic(new X509EncodedKeySpec(pubBytes));
            return new KeyPair(pub, priv);
        }

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();

        Files.writeString(privFile,
                Base64.getEncoder().encodeToString(kp.getPrivate().getEncoded()));
        Files.writeString(pubFile,
                Base64.getEncoder().encodeToString(kp.getPublic().getEncoded()));

        return kp;
    }

    public PaillierCryptosystem.KeyPair loadOrCreatePaillierKeyPair(String fileName)
            throws Exception {
        Path file = keyDirectory.resolve(fileName);

        if (Files.exists(file)) {
            Properties props = new Properties();
            try (InputStream in = Files.newInputStream(file)) {
                props.load(in);
            }
            BigInteger n      = new BigInteger(props.getProperty("n"),      16);
            BigInteger g      = new BigInteger(props.getProperty("g"),      16);
            BigInteger lambda = new BigInteger(props.getProperty("lambda"), 16);
            BigInteger mu     = new BigInteger(props.getProperty("mu"),     16);

            PaillierCryptosystem.PublicKey  pub  = new PaillierCryptosystem.PublicKey(n, g);
            PaillierCryptosystem.PrivateKey priv = new PaillierCryptosystem.PrivateKey(lambda, mu, pub);
            return new PaillierCryptosystem.KeyPair(pub, priv);
        }

        System.out.println("[KeyManager] Generating Paillier 2048-bit key pair (first run only – may take a moment)…");
        PaillierCryptosystem.KeyPair kp = PaillierCryptosystem.generateKeyPair(2048);

        Properties props = new Properties();
        props.setProperty("n",      kp.publicKey.n.toString(16));
        props.setProperty("g",      kp.publicKey.g.toString(16));
        props.setProperty("lambda", kp.privateKey.lambda.toString(16));
        props.setProperty("mu",     kp.privateKey.mu.toString(16));

        try (OutputStream out = Files.newOutputStream(file)) {
            props.store(out, "Paillier Key Pair — KEEP SECRET — do not share this file");
        }

        System.out.println("[KeyManager] Paillier key pair saved to " + file);
        return kp;
    }
}
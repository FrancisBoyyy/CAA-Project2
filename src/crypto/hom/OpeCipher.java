package crypto.hom;

public interface OpeCipher {
    long encrypt(long value);
    long decrypt(long token);
}
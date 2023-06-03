import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Алгоритм функціонує так,
 *  що Аліса і Боб знаючи числа
 *  prime та base
 *  можуть договоритись про спільний секретний ключ.
 */

public class DiffieHellman {
    private static final int bitLength; //розмір ключа
    //prime, base прості числа відомі обом користувачам
    private static final BigInteger prime;
    private static final BigInteger base;
    static {
        SecureRandom random = new SecureRandom();
        bitLength = 128;
        prime = BigInteger.probablePrime(bitLength, random);
        base = BigInteger.valueOf(2);
    }


    private final BigInteger privateKey;
    private final BigInteger publicKey;
    public DiffieHellman() {
        SecureRandom random = new SecureRandom();
        //privateKey = big generated user's number
        privateKey = new BigInteger(bitLength, random);
        //publicKey = base ^ privateKey mod prime
        publicKey = base.modPow(privateKey, prime);
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getSharedSecret(BigInteger otherPublicKey) {
        //sharedSecret = otherPublicKey ^ privateKey mod prime
        return otherPublicKey.modPow(privateKey, prime);
    }

    public static void main(String[] args) {
        DiffieHellman alice = new DiffieHellman();
        DiffieHellman bob = new DiffieHellman();

        // отримаємо публічні ключі іншого юзера
        BigInteger alicePublicKey = alice.getPublicKey();
        BigInteger bobPublicKey = bob.getPublicKey();

        //отримуємо спільний ключ
        BigInteger aliceSharedSecret = alice.getSharedSecret(bobPublicKey);
        BigInteger bobSharedSecret = bob.getSharedSecret(alicePublicKey);

        //перевірка результату:
        System.out.println("Alice's public key: " + alice.publicKey);
        System.out.println("Bob's public key: " + bob.publicKey);
        System.out.println();
        System.out.println("Alice's shared secret: " + aliceSharedSecret);
        System.out.println("Bob's shared secret: " + bobSharedSecret);

    }
}

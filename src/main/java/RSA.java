import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * 	Алгоритм виконання RSA
 * 	1)	Обираємо прості числа:
 * 	publicKey = 65537
 * 	Q, P
 * 	publicKey, N = P*Q – частини відкритого ключа
 * 	2)	Знаходимо обернене число до publicKey за модулем за допомогою методу modInverse()
 * 	3)	Шифруємо та розшифровуємо повідомлення за допомогою методів encrypt та decrypt відповідно
 */
public class RSA {
    //modulus = p * q, open for users
    private final BigInteger modulus;

    //open key, often number 65536 or 17
    //need for encrypting of message
    private final BigInteger publicKey;


    //secret key, need for decrypting of message
    private final BigInteger privateKey;

    /*
        (privateKey, p, q) - secret key
     */

    public RSA(int bitLength) {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);
        //p,q - випадкові прості числа
        modulus = p.multiply(q); // q * p

        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        // phq = (p - 1) * (q - 1)

        publicKey = new BigInteger("65537"); // Зазвичай використовуване значення
        privateKey = publicKey.modInverse(phi);
    }

    public BigInteger encrypt(BigInteger message) {
        /*
            Шифруємо повідомлення так, що:
            Encrypted message = message ^ publicKey mod p * q
         */
        return message.modPow(publicKey, modulus);
    }

    public BigInteger decrypt(BigInteger encryptedMessage) {
        /*
            Розшифровуємо повідомлення так, що:
            Decrypted message = encryptedMessage ^ privateKey mod p * q
         */
        return encryptedMessage.modPow(privateKey, modulus);
    }

    public static void main(String[] args) {
        RSA rsa = new RSA(1024);
        //зазвичає використовують довжину ключа 1024 біт

        //повідомення
        BigInteger message = new BigInteger("1234567890");
        System.out.println("Original Message: " + message);

        //шифрування повідомлення
        BigInteger encryptedMessage = rsa.encrypt(message);
        System.out.println("Encrypted Message: " + encryptedMessage);

        //розшифрування повідомлення
        BigInteger decryptedMessage = rsa.decrypt(encryptedMessage);
        System.out.println("Decrypted Message: " + decryptedMessage);
    }
}
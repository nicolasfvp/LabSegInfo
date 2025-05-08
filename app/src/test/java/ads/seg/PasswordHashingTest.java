package ads.seg;

import static org.junit.jupiter.api.Assertions.assertTrue;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import org.junit.jupiter.api.Test;

public class PasswordHashingTest {
    private static final SecureRandom S_RANDOM = new SecureRandom();

    @Test
    public void testHashPasswordWithMessageDigest() {
        byte[] salt = new byte[16];
        S_RANDOM.nextBytes(salt);
        String[] algorithms = { "MD5", "SHA-1", "SHA-256", "SHA-512" };

        byte[] hashedPassword;
        // Evite usar String para senhas, use char[] ou byte[]. A String é imutável e
        // pode ser
        // mantida na memória por mais tempo do que o necessário, tornando-a vulnerável
        // a ataques
        // de memória.
        // Use char[] ou byte[] para senhas, pois eles podem ser limpos da memória após
        // o uso.
        // Isso reduz a janela de oportunidade para um invasor acessar a senha.
        // java.util.Arrays.fill(password, '0'); // Limpa a senha após o uso
        char[] password = { '1', '2', '3', '4', '5', '6' }; // Senha a ser testada
        for (String algorithm : algorithms) {
            try {
                hashedPassword = PasswordHashing.hashPasswordWithMessageDigest(password, salt,
                        algorithm);
                assertTrue(PasswordHashing.verifyPasswordWithMessageDigest(password, salt,
                        algorithm, hashedPassword));
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    public void testHashPasswordWithPBKDF2() {
        byte[] salt = new byte[16];
        S_RANDOM.nextBytes(salt);
        int iterations = 600000;
        int keyLength = 128;
        String[] algorithms = { "PBKDF2WithHmacSHA1", "PBKDF2WithHmacSHA256", "PBKDF2WithHmacSHA512" };
        byte[] hashedPassword;
        char[] password = { '1', '2', '3', '4', '5', '6' }; // Senha a ser testada
        for (String algorithm : algorithms) {
            try {
                hashedPassword = PasswordHashing.hashPasswordWithPBKDF2(password, salt, algorithm,
                        iterations,
                        keyLength);
                assertTrue(PasswordHashing.verifyPasswordWithPBKDF2(password, salt, algorithm,
                        iterations, keyLength,
                        hashedPassword));
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                e.printStackTrace();
            }
        }
    }

    @Test
    public void testHashPasswordWithBCrypt() {
        char[] password = { '1', '2', '3', '4', '5', '6' }; // Senha a ser testada
        byte[] hashedPassword = PasswordHashing.hashPasswordWithBCrypt(password);
        assertTrue(PasswordHashing.verifyPasswordWithBCrypt(password, hashedPassword));
    }
}
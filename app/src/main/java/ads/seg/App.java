package ads.seg;
import java.io.Console;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Base64;
import java.util.Scanner;
import javax.swing.JOptionPane;
import javax.swing.JPasswordField;
import javax.swing.SwingUtilities;
/**
* Classe principal para testar a classe PasswordHashing com diferentes algoritmos de hash.
*/
public class App {
private static final SecureRandom S_RANDOM = new SecureRandom();
public static void main(String[] args) throws IOException {
Duration start, end;
String msg = "Hashed password with %s in %d nanoseconds.\n(base64): %s\n";
Base64.Encoder encoder = Base64.getEncoder();
byte[] salt = new byte[16];
S_RANDOM.nextBytes(salt);
String[] algorithms = { "MD5", "SHA-1", "SHA-256", "SHA-512" };
byte[] hashedPassword;
// Evite usar String para senhas, use char[] ou byte[]. A String é imutável e pode ser
// mantida na memória por mais tempo do que o necessário, tornando-a vulnerável a ataques
// de memória.
// Use char[] ou byte[] para senhas, pois eles podem ser limpos da memória após o uso.
// Isso reduz a janela de oportunidade para um invasor acessar a senha.
// java.util.Arrays.fill(password, '0'); // Limpa a senha após o uso
char[] password = {'1', '2', '3', '4', '5', '6'}; // Senha a ser testada
// Testando algoritmos de hash com message digest MD5, SHA-1, SHA-256, SHA-512 e
//comparando o tempo de execução
for (String algorithm : algorithms) {
try {
start = Duration.ofNanos(System.nanoTime());
hashedPassword = PasswordHashing.hashPasswordWithMessageDigest(password, salt,
algorithm);
end = Duration.ofNanos(System.nanoTime());
System.out.println(String.format(msg, algorithm, end.minus(start).toNanos(),
encoder.encodeToString(hashedPassword)));
} catch (NoSuchAlgorithmException e) {
e.printStackTrace();
}
}
int iterations = 210000; // Número de iterações

int keyLength = 128; // Tamanho da chave
String algorithm = "PBKDF2WithHmacSHA512";
// Testando algoritmos de hash com PBKDF2 e comparando o tempo de execução
try {
start = Duration.ofNanos(System.nanoTime());
hashedPassword = PasswordHashing.hashPasswordWithPBKDF2(password, salt, algorithm,
iterations, keyLength);
end = Duration.ofNanos(System.nanoTime());
System.out.println(String.format(msg, algorithm, end.minus(start).toNanos(), encoder.
encodeToString(hashedPassword)));
} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
e.printStackTrace();
}
// Testando algoritmo de hash BCrypt e comparando o tempo de execução
algorithm = "BCrypt";
start = Duration.ofNanos(System.nanoTime());
hashedPassword = PasswordHashing.hashPasswordWithBCrypt(password);
end = Duration.ofNanos(System.nanoTime());
System.out.println(String.format(msg, algorithm, end.minus(start).toNanos(), encoder.
encodeToString(hashedPassword)));
// Isso não funcionará em IDEs como IntelliJ IDEA ou se executar com o gradle run,
// pois o console não está disponível. Use o terminal ou o console do sistema operacional
// para testar.
// char[] s = System.console().readPassword("Entre com a senha: ");
// System.out.println("Senha: " + new String(s));
}
}
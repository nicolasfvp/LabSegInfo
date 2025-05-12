package ads.seg;

import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder;


public class HashService {
    private final BCryptPasswordEncoder BCryptPasswordEncoder;
    private final Pbkdf2PasswordEncoder Pbkdf2PasswordEncoder;
    public HashService(BCryptPasswordEncoder bCryptPasswordEncoder,
            Pbkdf2PasswordEncoder pbkdf2PasswordEncoder) {
        BCryptPasswordEncoder = bCryptPasswordEncoder;
        Pbkdf2PasswordEncoder = pbkdf2PasswordEncoder;
    }

    public String hashSenha(String senha, Algoritmos alg){
        switch (alg) {
            case pbkdf2:
                return Pbkdf2PasswordEncoder.encode(senha);
                
            case bcrypt:
                return BCryptPasswordEncoder.encode(senha);
        
            default:

                throw new RuntimeException("modelo de encriptacao nao definido");
        }
    }

    public boolean matchSenha(String senha, String senhaEncriptada){
        
    }
 
}

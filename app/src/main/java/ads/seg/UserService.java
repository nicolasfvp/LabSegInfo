package ads.seg;

import java.util.ArrayList;
import java.util.List;

public class UserService {
    
    List<User> bdc = new ArrayList<>();

    Algoritmos algoritmoEncriptacao = Algoritmos.bcrypt;

    public UserService(Algoritmos algoritmo){
        algoritmoEncriptacao = algoritmo;
    }

    public void register(String login, byte[] senha){
        
        if(bdc.stream().filter(user -> user.get_login().equals(login)).findFirst() != null){
            throw new RuntimeException("Usuario existente");
        }

        User novoUser = new User(login, senha);

        bdc.add(novoUser);
    }

    public void updatePassword(String login, byte[] senhaNova, byte[] senha){
        User usuario = bdc.stream().filter(user -> user.get_login().equals(login)).findFirst().orElse(null);

        if(usuario == null){
            throw new RuntimeException("Usuario inexistente");
        }
        if(!usuario.get_senha().equals(senha)){
            throw new RuntimeException("senha errada");
        }
        
        // permitir a escolha do hash novo

        // passar o hash na nova senha

        
        bdc.remove(usuario);
        usuario.set_senha(senhaNova);
        bdc.add(usuario);
    }

    public String authenticate(String login, byte[] senha){
        User usuario = bdc.stream().filter(user -> user.get_login().equals(login)).findFirst().orElse(null);

        if(usuario == null){
            return "Usuario ou senha errado";
        }
        if(usuario.get_senha().equals(senha)){
            return "Usuario ou senha errado";
        }
        return "Autenticado com sucesso";
    }

    public byte[] hashSenha(String senha){
        
    }
}

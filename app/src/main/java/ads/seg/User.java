package ads.seg;

public class User {
    private String login;
    private byte[] senha;

    public String get_login() {
        return login;
    }

    public void set_login(String _login) {
        this.login = _login;
    }

    public byte[] get_senha() {
        return senha;
    }

    public void set_senha(byte[] _senha) {
        this.senha = _senha;
    }

    public User(String login, byte[] senha){
        this.login = login;
        this.senha = senha;
    }

}

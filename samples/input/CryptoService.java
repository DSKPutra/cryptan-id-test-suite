// Contoh source code produk (ILUSTRATIF) — Java JCA
import javax.crypto.*;
import java.security.*;

public class CryptoService {
    SecretKey newKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        return kg.generateKey();
    }
    byte[] seal(SecretKey k, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, k);
        return c.doFinal(pt);
    }
    KeyPair rsa() throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(3072);
        return g.generateKeyPair();
    }
    byte[] wrap(PublicKey pk, byte[] key) throws Exception {
        Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        c.init(Cipher.ENCRYPT_MODE, pk);
        return c.doFinal(key);
    }
    byte[] mac(SecretKey k, byte[] m) throws Exception {
        Mac h = Mac.getInstance("HmacSHA384");
        h.init(k);
        return h.doFinal(m);
    }
}

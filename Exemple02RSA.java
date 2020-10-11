
import javax.crypto.Cipher;
import java.security.*;
import java.util.Base64;
import java.util.Set;

public class Exemple02RSA {
    public static void main(String[] args)throws Exception {
        String missatge = "Hola mon. Això es un missatge de prova llarg. I amb aquesta frase l'allarguem encar més.";

        KeyPairGenerator keyPairFactory = KeyPairGenerator.getInstance("RSA");
        keyPairFactory.initialize(1024); // >1024 strong encription

        KeyPair keys = keyPairFactory.generateKeyPair();
        PrivateKey privateKey = keys.getPrivate();
        PublicKey publicKey = keys.getPublic();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        //String encryptedMessage = Base64.getEncoder().encodeToString(cipher.doFinal(missatge.getBytes()));
        byte[] encryptedMessage = cipher.doFinal(missatge.getBytes());
        System.out.println("Encryptied: " + hex(encryptedMessage));

        //Desencriptar

        Cipher decipher = Cipher.getInstance("RSA");
        decipher.init(Cipher.DECRYPT_MODE, publicKey);

        //String decryptedMessage = new String(decifer.doFinal(Base64.getDecoder().decode(encryptedMessage)));
        String decryptedMessage = new String(decipher.doFinal(encryptedMessage));

        System.out.println("Decrypted: " + decryptedMessage);

    }

    private static String hex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i=0; i<bytes.length; i++) {
            sb.append(String.format("%02X ",bytes[i]));
        }
        return sb.toString();
    }
}

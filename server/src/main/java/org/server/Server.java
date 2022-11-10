package org.server;

import javax.crypto.*;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class Server {
    private final static int KEYBITESIZE = 256;

    private static Socket clientSocket;
    //private static ServerSocket server;
    private static BufferedReader in;
    private static BufferedWriter out;

    public static void main(String[] args) {
        try (ServerSocket server = new ServerSocket(3345)){
            clientSocket = server.accept();
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
            while(clientSocket.isConnected()){
                out.write("Choose what you wanna do: \n");
                out.write("1 - Asymmetric encryption RSA \n");
                out.write("2 - Symmetric encryption AES \n");
                out.write("3 - Exit from the program \n");
                out.flush();
                int caseN = -1;
                try {
                    caseN = Integer.parseInt(in.readLine());
                }
                catch (Exception e){
                    out.write("I don't understand what you wrote:(\n\n");
                    out.flush();
                }
                switch (caseN) {
                    case 1 -> asymEncryption();
                    case 2 -> symEcryption();
                    case 3 -> {
                        out.write("You're getting disconnected...\ndisconnect\n");
                        out.flush();
                    }
                    default -> {
                    }
                }
            }
        }
        catch (Exception e){
            System.out.println(e);
        }
    }
    private static void asymEncryption() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException {
        out.write("---------------------------------\n");
        out.write("You chose asymmetric encryption!\n");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2056);
        KeyPair keyPair = kpg.generateKeyPair();
        out.write("You got the public key to encrypt the message\n");
        out.write("KeyPair\n");
        out.flush();
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        oos.writeObject(keyPair.getPublic());
        out.flush();
        String entry = in.readLine();
        out.write("Server got the encrypted message: " + entry);
        Cipher encryptCipher = Cipher.getInstance( "RSA");
        encryptCipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        byte [] bytes = encryptCipher.doFinal(Base64.getDecoder().decode(entry));
        out.write("\nEncrypting it...");
        out.flush();
        Thread.sleep(1000);
        out.write("\nGot it!\nThe message is \"" + new String(bytes, StandardCharsets.UTF_8) + "\"\n\n\n");
        out.flush();
        Thread.sleep(2000);
    }
    private static void symEcryption() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InterruptedException {
        out.write("---------------------------------\n");
        out.write("You chose symmetric encryption!\n");
        out.write("You got the key to encrypt the message!\n");
        out.flush();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(KEYBITESIZE, new SecureRandom());
        SecretKey secretKey = keyGenerator.generateKey();
        out.write("SecretKey\n");
        out.flush();
        ObjectOutputStream oos = new ObjectOutputStream(clientSocket.getOutputStream());
        oos.writeObject(secretKey);
        out.flush();
        //Получаю зашифрованное сообщение
        String entry = in.readLine();
        out.write("Server got the encrypted message: " + entry);
        out.write("\nDecrypting it...\n");
        out.flush();
        Thread.sleep(1000);
        Cipher decryptCipher = Cipher.getInstance("AES");
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] bytes = decryptCipher.doFinal(Base64.getDecoder().decode(entry));
        out.write("We decrypted it!\nThe message is: " + new String(bytes, StandardCharsets.UTF_8));
        out.write("\n\n\n");
        out.flush();
        Thread.sleep(2000);
    }
}

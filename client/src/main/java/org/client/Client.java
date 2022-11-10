package org.client;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;

public class Client {
    public static void main(String[] args) {
        try(Socket socket = new Socket("localhost", 3345);
            BufferedReader consoleReader = new BufferedReader(new InputStreamReader(System.in));
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream())))
        {
            System.out.println("Client connected to socket.");
            System.out.println();
            while(!socket.isOutputShutdown()) {
                while (in.ready()) {
                    String wordsToHandle = in.readLine();
                    if (wordsToHandle.equalsIgnoreCase("SecretKey")){
                        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                        SecretKey secretKey = (SecretKey) ois.readObject();
                        Cipher encryptCipher = Cipher.getInstance("AES");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, secretKey);
                        System.out.println("Write your message");
                        String bytes = Base64.getEncoder()
                                .encodeToString(encryptCipher.doFinal(consoleReader.readLine().getBytes(StandardCharsets.UTF_8)));
                        out.write(bytes + "\n");
                        out.flush();
                    }
                    else if (wordsToHandle.equalsIgnoreCase("KeyPair")){
                        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
                        Key key = (Key) ois.readObject();
                        System.out.println("Write the message to encrypt");
                        String textToEncrypt = consoleReader.readLine();
                        Cipher encryptCipher = Cipher.getInstance("RSA");
                        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
                        String bytes = Base64
                                .getEncoder().encodeToString(encryptCipher.doFinal(textToEncrypt.getBytes(StandardCharsets.UTF_8)));
                        out.write(bytes + "\n");
                        out.flush();
                    }
                    else if (wordsToHandle.equalsIgnoreCase("disconnect")){
                        return;
                    }
                    else System.out.println(wordsToHandle);
                }
                if (consoleReader.ready()) {
                    String word = consoleReader.readLine();
                    out.write(word + "\n");
                    out.flush();

                }


            }
        }
        catch (Exception e){
            System.out.println(e);
        }
    }
}
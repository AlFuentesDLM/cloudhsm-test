package com.amazonaws.cloudhsm.examples;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.Objects;
import com.cavium.key.CaviumKey;

public class DESedeECBEncrypt {
    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }
        Integer handle = null;
        String message = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    System.out.println("Key handle from the hsm: "+handle);
                    break;
                case "--message":
                    message = args[++i];
                    System.out.println("Cipher text: "+message);
                    break;
                case "--help":
                    System.out.println("--handle Key handle");
                    System.out.println("--message Message to decrypt");
                    System.out.println("--help");
            }
        }
        if (Objects.isNull(handle) ||  Objects.isNull(message)){
            System.out.println("Error: Message or handle is missing");
            throw new Exception();
        }

        CaviumKey caviumKey =  KeyUtilitiesRunner.getKeyByHandle((long)handle);
        System.out.println("Getting the following key from the HSM: "+caviumKey.getLabel());
        Key key = (Key) caviumKey;

        byte[] encryptedText = encrypt(key, message.getBytes());
        System.out.println("Successful encrypt");
        System.out.println("Encrypt message b64 encoded: "+ Base64.getEncoder().encodeToString(encryptedText));
    }


    /**
     * Encrypt some plaintext using the DESede ECB cipher mode.
     * @param key
     * @param plainText
     * @return byte[] containing encrypted data
     */
    public static byte[] encrypt(Key key, byte[] plainText) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "Cavium");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            return encCipher.doFinal(plainText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
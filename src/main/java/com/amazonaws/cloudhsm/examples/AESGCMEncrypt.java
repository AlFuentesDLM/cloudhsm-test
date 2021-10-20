package com.amazonaws.cloudhsm.examples;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import com.cavium.key.CaviumKey;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.Security;
import java.util.Base64;

public class AESGCMEncrypt {
    private static String helpString = "AESGCM Encrypt method\n" +
            "This sample demonstrates how to encrypt a message using a key from the hsm.\n" +
            "\n" +
            "Options\n" +
            "\t[--handle <numeric key handle>]\n" +
            "\t--message\t\tmessage to be encrypted\n\n";

    public static void main(String[] args) throws Exception{
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }
        Integer handle = null;
        String message = null;
        SymmetricKeys.generateDESKey("destest");
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    System.out.println("Key handle from the hsm: "+handle);
                    break;
                case "--message":
                    message = args[++i];
                    System.out.println("Message to be encrypted: "+message);
                    break;
                case "--help":
                    System.out.println(helpString);
            }
        }
        if (Objects.isNull(handle) ||  Objects.isNull(message)){
            System.out.println("Error: Message or handle is missing");
            throw new Exception();
        }
        String aad = "16 bytes of date";
        CaviumKey caviumKey =  KeyUtilitiesRunner.getKeyByHandle((long)handle);
        System.out.println("Getting the following key from the HSM: "+caviumKey.getLabel());
        Key key = (Key) caviumKey;
        byte[] plainText = message.getBytes();
        List<byte[]> result = encrypt(key,plainText, aad.getBytes());
        byte[] iv = result.get(0);
        byte[] cipherText = result.get(1);
        System.out.printf("Raw IV encoded b64: ");
        System.out.println(Base64.getEncoder().encodeToString(iv));
        System.out.printf("IV: ");
        for (int i=0; i<iv.length; i++) {
            System.out.printf("%02X", iv[i]);
        }
        System.out.println("");
        System.out.printf("Cipher message encoded b64: ");
        System.out.println(Base64.getEncoder().encodeToString(cipherText));
    }

    public static List<byte[]> encrypt(Key key, byte[] plainText, byte[] aad) {
        try {
            // Create an encryption cipher.
            Cipher encCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
            encCipher.init(Cipher.ENCRYPT_MODE, key);
            encCipher.updateAAD(aad);
            encCipher.update(plainText);
            byte[] ciphertext = encCipher.doFinal();

            // The IV is generated inside the HSM. It is needed for decryption, so
            // both the ciphertext and the IV are returned.
            return Arrays.asList(encCipher.getIV(), ciphertext);
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }

}
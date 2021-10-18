/*
 * Copyright 2018 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of this
 * software and associated documentation files (the "Software"), to deal in the Software
 * without restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
 * INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package com.amazonaws.cloudhsm.examples;

import com.cavium.key.CaviumKey;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

/**
 * This sample demonstrates how to encrypt data with AES GCM. It shows where the IV is generated
 * and how to pass authenticated tags to the encrypt and decrypt functions.
 */
public class AESGCMDecrypt {
    private static String helpString = "AESGCM Decrypt method\n" +
            "This sample demonstrates how to Decrypt a message using a key from the hsm.\n" +
            "\n" +
            "Options\n" +
            "\t[--handle <numeric key handle>]\n" +
            "\t--cipher-text\t\tbase64 of the cipher message \n\n"+
            "\t--iv\t\tbase64 of the iv \n\n";

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }
        Integer handle = null;
        String cipherText = null;
        String iv = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    System.out.println("Key handle from the hsm: "+handle);
                    break;
                case "--cipher-text":
                    cipherText = args[++i];
                    System.out.println("Message to be decypted in b64: "+cipherText);
                    break;
                case "--iv":
                    iv = args[++i];
                    System.out.println("IV b64"+iv);
                    break;
                case "--help":
                    System.out.println(helpString);
                    break;
            }
        }
        if (Objects.isNull(handle) ||  Objects.isNull(iv) || Objects.isNull(cipherText)){
            System.out.println("Error: iv, cipher-text or handle is missing");
            System.out.println(helpString);
            throw new Exception();
        }

        String aad = "16 bytes of data";
        CaviumKey caviumKey =  KeyUtilitiesRunner.getKeyByHandle((long)handle);
        Key key = (Key) caviumKey;
        System.out.println("Getting the following key from the HSM: "+caviumKey.getLabel());
        byte[] decodedIV =  Base64.getDecoder().decode(iv);
        byte[] decodedText = Base64.getDecoder().decode(cipherText);
        // Decrypt the ciphertext.
        byte[] decryptedText = decrypt(key, decodedText, decodedIV, aad.getBytes());
        System.out.println("Raw decrypted message: "+new String(decryptedText));
    }

    /**
     * Decrypt the ciphertext using the HSM supplied IV and the user supplied tag data.
     * @param key
     * @param cipherText
     * @param iv
     * @param aad
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText, byte[] iv, byte[] aad) {
        Cipher decCipher;
        try {
            // Only 128 bit tags are supported
            GCMParameterSpec gcmSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);

            decCipher = Cipher.getInstance("AES/GCM/NoPadding", "Cavium");
            decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
            decCipher.updateAAD(aad);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        return null;
    }
}
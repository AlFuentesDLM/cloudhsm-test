/*pyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import com.cavium.key.CaviumKey;


/**
 * This sample demonstrates how to encrypt data with DESede ECB.
 */
public class DESedeECBDecrypt {

    public static void main(String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        Integer handle = null;
        String cipherText = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    System.out.println("Key handle from the hsm: "+handle);
                    break;
                case "--cipher-message":
                    cipherText = args[++i];
                    System.out.println("Cipher text: "+cipherText);
                    break;
                case "--help":
                    System.out.println("--handle Key handle");
                    System.out.println("--cipher-message Message to decrypt");
                    System.out.println("--help");
            }
        }
        if (Objects.isNull(handle) ||  Objects.isNull(cipherText)){
            System.out.println("Error: Message or handle is missing");
            throw new Exception();
        }

        CaviumKey caviumKey =  KeyUtilitiesRunner.getKeyByHandle((long)handle);
        Key key = (Key) caviumKey;

        byte[] decodedCipherText = Base64.getDecoder().decode(cipherText.getBytes());
        byte[] decryptedText = decrypt(key, decodedCipherText);
        System.out.println("Successful decryption");
        System.out.println("Decrypted message: "+new String(decryptedText));
    }



    /**
     * Decrypt the ciphertext using the DESede ECB cipher mode.
     * @param key
     * @param cipherText
     * @return byte[] of the decrypted ciphertext.
     */
    public static byte[] decrypt(Key key, byte[] cipherText) {
        Cipher decCipher;
        try {
            decCipher = Cipher.getInstance("DESede/ECB/PKCS5Padding", "Cavium");
            decCipher.init(Cipher.DECRYPT_MODE, key);
            return decCipher.doFinal(cipherText);

        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
        }
        return null;
    }
}
/*opyright 2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
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
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Base64;
import java.util.Objects;
import javax.crypto.Mac;

import com.cavium.key.CaviumKey;

/**
 * Demonstrate basic HMAC operation.
 */
public class HMACOperationsRunner {

    /**
     * Digest a message using the passed algorithm.
     * Supported digest types are documented here: https://docs.aws.amazon.com/cloudhsm/latest/userguide/java-lib-supported.html
     *
     * @param message
     * @param key
     * @param algorithm
     * @param provider
     * @return
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchProviderException
     */
    public static byte[] digest(byte[] message, Key key, String algorithm, String provider)
            throws InvalidKeyException, NoSuchAlgorithmException, NoSuchProviderException {
        Mac mac = Mac.getInstance(algorithm, provider);
        mac.init(key);
        mac.update(message);
        return mac.doFinal();
    }

    public static void main(final String[] args) throws Exception {
        try {
            Security.addProvider(new com.cavium.provider.CaviumProvider());
        } catch (IOException ex) {
            System.out.println(ex);
            return;
        }

        String text = null;
        Integer handle = null;
        String fileName = null;
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case "--handle":
                    handle = Integer.valueOf(args[++i]);
                    System.out.println("Key handle from the hsm: " + handle);
                    break;
                case "--message":
                    text = args[++i];
                    System.out.println("Message to be encrypted: " + text);
                    break;
                case "--file":
                    fileName = args[++i];
                    System.out.println("File name: "+fileName);
                    break;
                case "--help":
                    System.out.println("--handle Handle of the key stored in the hsm");
                    System.out.println("--message");
                    System.out.println("--file");
                    System.out.println("--help");
                    break;
            }
        }
        if (Objects.isNull(handle)) {
            throw new Exception("Handle is missing");
        }
        if (fileName != null && text == null) {
            text = readFile(fileName);
            System.out.println("File content: "+text);
        }
        CaviumKey caviumKey = KeyUtilitiesRunner.getKeyByHandle((long) handle);
        System.out.println("Getting the following key from the HSM: " + caviumKey.getLabel());
        Key key = (Key) caviumKey;
        String algorithm = "HmacSHA512";
        System.out.println("Using the following algo: " + algorithm);
        byte[] caviumDigest = digest(text.getBytes("UTF-8"), key, algorithm, "Cavium");
        System.out.println("Cavium HMAC= " + Base64.getEncoder().encodeToString(caviumDigest));
    }

    public static String readFile(String location) {
        String content = "";
        try {
            content = new String(Files.readAllBytes(Paths.get(location)));
        } catch (IOException e) {
            e.printStackTrace();
        }
        return content;
    }
}
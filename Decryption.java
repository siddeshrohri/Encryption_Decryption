import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;

public class Decryption {
    public static void main(String[] args) throws Exception {
        // Input path to the encrypted file
        String inputFilePath = "C:/Users/sidde/Desktop/Java Encryption and Decryption Algorithms/encryptedFile.enc";

        // Get the password from the user
        Scanner scanner = new Scanner(System.in);
        System.out.print("Enter the password to decrypt the file: ");
        String password = scanner.nextLine();

        // Decrypt the file with the provided password
        decryptFile(inputFilePath, password);

        System.out.println("File successfully decrypted!");
    }

    /**
     * Decrypts the encrypted file using the provided password.
     *
     * @param inputFilePath The path to the encrypted file to be decrypted.
     * @param password      The password used for decryption.
     * @throws Exception If an error occurs during the decryption process.
     */

    private static void decryptFile(String inputFilePath, String password) throws Exception {
        // Read the salt and IV from the encrypted file
        byte[] salt = new byte[16];
        byte[] iv = new byte[16];

        try (FileInputStream inputStream = new FileInputStream(inputFilePath)) {
            inputStream.read(salt);
            inputStream.read(iv);
        }

        // Generate a secret key from the provided password and salt
        SecretKey secretKey = generateAESKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));

        // Extract the file extension and delimiter from the input file
        String fileExtension;
        try (FileInputStream inputStream = new FileInputStream(inputFilePath)) {
            inputStream.skip(salt.length + iv.length);
            StringBuilder extensionBuilder = new StringBuilder();
            int ch;
            while ((ch = inputStream.read()) != -1) {
                if (ch == '|') break;
                extensionBuilder.append((char) ch);
            }
            fileExtension = extensionBuilder.toString();
        }

        // Create the output file path with the desired file extension
        String outputFilePath = "C:/Users/sidde/Desktop/Java Encryption and Decryption Algorithms/decryptedFile." + fileExtension;

        try (FileInputStream inputStream = new FileInputStream(inputFilePath);
             FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            // Skip the salt, IV, extension, delimiter, and HMAC bytes to start reading the encrypted data
            int headerSize = salt.length + iv.length + fileExtension.length() + 1;
            inputStream.skip(headerSize);

            // Buffer to read and decrypt data in smaller chunks
            byte[] inputBuffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                byte[] decryptedBytes = cipher.update(inputBuffer, 0, bytesRead);
                outputStream.write(decryptedBytes);
            }

            // Write the final block of decrypted data
            byte[] finalBlock = cipher.doFinal();
            outputStream.write(finalBlock);
        }
    }

    /**
     * Generates a secret key for AES decryption based on the password and salt.
     *
     * @param password The password used to generate the secret key.
     * @param salt     The salt used for key derivation.
     * @return The generated secret key as a SecretKey object.
     * @throws NoSuchAlgorithmException If the specified cryptographic algorithm is not available.
     * @throws InvalidKeySpecException  If the provided key specification is invalid.
     */

    private static SecretKey generateAESKey(String password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        int iterations = 65536;
        int keyLength = 256;
        KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, iterations, keyLength);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        byte[] keyBytes = secretKeyFactory.generateSecret(keySpec).getEncoded();
        return new SecretKeySpec(keyBytes, "AES");
    }
}

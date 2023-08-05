import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class Encryption {
    public static void main(String[] args) throws Exception {
        // Input path to the file you want to encrypt
        String inputFilePath = "C:/Users/sidde/Desktop/Java Encryption and Decryption Algorithms/style.css";
        // Output path for the encrypted File
        String outputFilePath = "C:/Users/sidde/Desktop/Java Encryption and Decryption Algorithms/encryptedFile.enc";
        // Generate a random secure password of 64 bits
        String password = generateRandomPassword(64); // 64-bit password, assuming 8 characters
        // Save the password to a file
        savePasswordToFile(password);
        // Encrypt the file
        encryptFile(inputFilePath, outputFilePath, password);
        System.out.println("File successfully encrypted!");
    }

    /**
    * Generates a random and secure password of the specified length by combining characters from different character sets.
    *
    * @param length The desired length of the password.
    * @return A randomly generated password as a String.
    */

    private static String generateRandomPassword(int length) {
        String upperChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerChars = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String specialChars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/";

        String allChars = upperChars + lowerChars + digits + specialChars;
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder password = new StringBuilder(length);

        for (int i = 0; i < length; i++) {
            int randomIndex = secureRandom.nextInt(allChars.length());
            char randomChar = allChars.charAt(randomIndex);
            password.append(randomChar);
        }

        return password.toString();
    }

    /**
     * Saves the provided password to a file named "password.txt" in the current working directory.
     *
     * @param password The password to be saved.
     * @throws IOException If an I/O error occurs while writing the password to the file.
     */

    private static void savePasswordToFile(String password) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream("password.txt")) {
            outputStream.write(password.getBytes());
        }
    }

    /**
     * Encrypts the specified input file using AES encryption with the provided password.
     *
     * @param inputFilePath  The path to the file that needs to be encrypted.
     * @param outputFilePath The path to the encrypted output file where the encrypted data will be saved.
     * @param password       The password used for encryption.
     * @throws Exception If an error occurs during the encryption process.
     */

    private static void encryptFile(String inputFilePath, String outputFilePath, String password) throws Exception {
        // Generate a random salt for password-based key derivation
        byte[] salt = new byte[16];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(salt);

        // Derive a secret key from the generated password and salt
        SecretKey secretKey = generateAESKey(password, salt);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        // Get the initialization vector (IV) used during encryption
        byte[] iv = cipher.getIV();

        // Extract the file extension from the input file path
        String fileExtension = getFileExtension(inputFilePath);

        // Write the salt, IV, file extension, and delimiter to the output file
        try (FileOutputStream outputStream = new FileOutputStream(outputFilePath)) {
            outputStream.write(salt);
            outputStream.write(iv);
            outputStream.write(fileExtension.getBytes());
            outputStream.write('|'); // Delimiter
        }

        try (FileInputStream inputStream = new FileInputStream(inputFilePath);
             FileOutputStream outputStream = new FileOutputStream(outputFilePath, true)) {
            byte[] inputBuffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                byte[] encryptedBytes = cipher.update(inputBuffer, 0, bytesRead);
                outputStream.write(encryptedBytes);
            }

            // Write the final block of encrypted data
            byte[] finalBlock = cipher.doFinal();
            outputStream.write(finalBlock);
        }
    }

    /**
     * Generates an AES secret key for encryption based on the provided password and salt.
     *
     * @param password The password used for key derivation.
     * @param salt     The random salt used for key derivation.
     * @return A SecretKey object containing the generated AES secret key.
     * @throws NoSuchAlgorithmException If the specified algorithm is not available.
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

    /**
     * Extracts the file extension from the given file path.
     *
     * @param filePath The file path from which the extension needs to be extracted.
     * @return The extracted file extension in lowercase as a String.
     *         If no file extension is found or the dot is at the end of the file path, an empty string is returned.
     */

    private static String getFileExtension(String filePath) {
        int dotIndex = filePath.lastIndexOf(".");
        if (dotIndex == -1 || dotIndex == filePath.length() - 1) {
            return ""; // No extension or dot is at the end of the file path
        }
        return filePath.substring(dotIndex + 1).toLowerCase();
    }
}

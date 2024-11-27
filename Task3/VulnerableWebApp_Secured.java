import java.sql.*;
import java.util.Scanner;
public class VulnerableWebApp_Secured {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        // Use prepared statements to prevent SQL injection
        String query = "SELECT * FROM users WHERE username = ? AND password = ?";
        try (Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "password");
             PreparedStatement preparedStatement = connection.prepareStatement(query)) {
             
            preparedStatement.setString(1, username);
            preparedStatement.setString(2, password);
            ResultSet rs = preparedStatement.executeQuery();

            if (rs.next()) {
                System.out.println("Login successful!");
            } else {
                System.out.println("Invalid credentials.");
            }
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
        }

        // Hash the password before storing it
        System.out.print("Create a new password: ");
        String newPassword = scanner.nextLine();
        String hashedPassword = hashPassword(newPassword);
        storePassword(hashedPassword);

        // Use a secure method to generate session IDs
        String sessionId = generateSecureSessionId();
        System.out.println("Your session ID is: " + sessionId);

        // Sanitize user input to prevent XSS
        System.out.print("Enter your comment: ");
        String comment = scanner.nextLine();
        System.out.println("<div>" + sanitizeInput(comment) + "</div>");

        // Avoid hardcoded credentials; load them from a secure environment
        String hardcodedAdminUsername = System.getenv("ADMIN_USERNAME");
        String hardcodedAdminPassword = System.getenv("ADMIN_PASSWORD");
        if (username.equals(hardcodedAdminUsername) && password.equals(hardcodedAdminPassword)) {
            System.out.println("Welcome, Admin!");
        } else {
            System.out.println("Invalid credentials.");
        }

        // Log errors instead of printing stack traces
        try {
            throw new SQLException("Database error occurred");
        } catch (SQLException e) {
            System.err.println("An error occurred: " + e.getMessage());
        }
    }

    // Method to securely hash passwords
    public static String hashPassword(String password) {
        try {
            java.security.MessageDigest digest = java.security.MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    // Simulate password storage
    public static void storePassword(String password) {
        System.out.println("Password securely stored: " + password);
    }

    // Generate a secure session ID
    public static String generateSecureSessionId() {
        return java.util.UUID.randomUUID().toString();
    }

    // Sanitize input to prevent XSS
    public static String sanitizeInput(String input) {
        return input.replaceAll("[<>]", "");
    }
}



import java.sql.*;
import java.util.Scanner;

public class VulnerableWebApp {
    
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        try (Connection connection = DriverManager.getConnection("jdbc:mysql://localhost:3306/db", "root", "password")) {
            String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);

            if (rs.next()) {
                System.out.println("Login successful!");
            } else {
                System.out.println("Invalid credentials.");
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        
        System.out.print("Create a new password: ");
        String newPassword = scanner.nextLine();
        storePassword(newPassword);
        
        String sessionId = "12345";
        System.out.println("Your session ID is: " + sessionId);

        System.out.print("Enter your comment: ");
        String comment = scanner.nextLine();
        System.out.println("<div>" + comment + "</div>");
        
        String hardcodedAdminUsername = "admin";
        String hardcodedAdminPassword = "admin123";
        if (username.equals(hardcodedAdminUsername) && password.equals(hardcodedAdminPassword)) {
            System.out.println("Welcome, Admin!");
        } else {
            System.out.println("Invalid credentials.");
        }

        try {
            throw new SQLException("Database error occurred");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void storePassword(String password) {
        System.out.println("Storing password: " + password);
    }
}

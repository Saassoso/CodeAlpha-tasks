
## Vulnerable Code Overview
This project contains two Java files:
1. `VulnerableCode.java`: The original code with identified vulnerabilities.
2. `SecureCode.java`: The updated code following secure coding practices.

## Identified Vulnerabilities
1. **SQL Injection:** Concatenation of user inputs into SQL queries.
2. **Insecure Password Storage:** Plaintext password storage and display.
3. **Hardcoded Credentials:** Sensitive admin credentials in the code.
4. **Cross-Site Scripting (XSS):** Unsanitized user input rendered in HTML.

## Secure Solutions Implemented
1. Replaced concatenated SQL queries with prepared statements.
2. Utilized bcrypt hashing for secure password storage.
3. Used environment variables for sensitive credentials.
4. Sanitized user input to prevent XSS attacks.

## How to Run
1. Compile and run `SecureCode.java`:
   ```bash
   javac SecureCode.java
   java SecureCode
   ```
2. Follow the prompts to test the secure implementation.

## Requirements
- Java Development Kit (JDK) installed.
- MySQL database setup (if needed for testing SQL).
- Environment variables configured for admin credentials:
  ```bash
  export ADMIN_USERNAME=your_admin_username
  export ADMIN_PASSWORD=your_admin_password
  ```

import os
from sentence_transformers import SentenceTransformer, util
from annoy import AnnoyIndex
import sys

# Load the advanced SentenceTransformer model
model = SentenceTransformer('sentence-transformers/all-mpnet-base-v2', device='cpu')

# Retrieve command-line arguments
name = sys.argv[1]  # this should be repo name or id

files = {'index.php': "<?php\nrequire __DIR__ . '/../vendor/autoload.php';\n\nuse Dotenv\\Dotenv;\n\n// Load environment variables\n$dotenv = Dotenv::createImmutable(__DIR__ . '/../');\n$dotenv->load();\n\n// Include application logic\nrequire __DIR__ . '/../src/App.php';\n\n$app = new App();\n$app->run();",
 'app.php': '<?php\n\nclass App\n{\n    private $db;\n\n    // Configuration settings\n    private $config = [\n        \'encryption\' => [\n            \'algorithm\' => \'AES-256-CBC\',\n            \'key\' => \'your-encryption-key\', // Change to your actual encryption key (32 bytes for AES-256)\n            \'iv_length\' => 16\n        ],\n        \'hashing\' => [\n            \'algorithm\' => PASSWORD_DEFAULT,\n            \'options\' => [\'cost\' => 12]\n        ],\n        \'random\' => [\n            \'guid_length\' => 16,\n            \'file_name_length\' => 16,\n            \'string_length\' => 16\n        ]\n    ];\n\n    public function __construct()\n    {\n        $this->connectToDatabase();\n    }\n\n    private function connectToDatabase()\n    {\n        $host = getenv(\'DB_HOST\');\n        $db   = getenv(\'DB_NAME\');\n        $user = getenv(\'DB_USER\');\n        $pass = getenv(\'DB_PASS\');\n        $charset = \'utf8mb4\';\n\n        $dsn = "mysql:host=$host;dbname=$db;charset=$charset";\n        $options = [\n            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,\n            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,\n            PDO::ATTR_EMULATE_PREPARES   => false,\n        ];\n\n        try {\n            $this->db = new PDO($dsn, $user, $pass, $options);\n        } catch (PDOException $e) {\n            error_log($e->getMessage());\n            if (getenv(\'APP_ENV\') === \'development\') {\n                throw new PDOException($e->getMessage(), (int)$e->getCode());\n            } else {\n                throw new Exception(\'Database connection failed.\');\n            }\n        }\n    }\n\n    public function run()\n    {\n        // Application logic here\n        echo "Application is running.";\n\n        $user = $this->getUserById(1);\n        echo htmlspecialchars(json_encode($user), ENT_QUOTES, \'UTF-8\');\n    }\n\n    public function getUserById($id)\n    {\n        if (!is_numeric($id)) {\n            throw new InvalidArgumentException(\'Invalid user ID.\');\n        }\n\n        $stmt = $this->db->prepare(\'SELECT * FROM users WHERE id = :id\');\n        $stmt->execute([\'id\' => $id]);\n        return $stmt->fetch();\n    }\n\n// Function to validate and sanitize input\n    function sanitizeInput($data) {\n        return htmlspecialchars(stripslashes(trim($data)));\n    }\n\n    // Function to validate password\n    function validatePassword($password) {\n        // Remove multiple spaces\n        $password = preg_replace(\'/\\s+/\', \' \', $password);\n        // Check if password length is at least 12 characters\n        return strlen($password) >= 12;\n    }\n\n// Function to generate a secure random GUID\n    function generateGuid($length) {\n        $data = random_bytes($length);\n        assert(strlen($data) == $length);\n\n        // Set version to 0100\n        $data[6] = chr(ord($data[6]) & 0x0f | 0x40);\n        // Set bits 6-7 to 10\n        $data[8] = chr(ord($data[8]) & 0x3f | 0x80);\n\n        return vsprintf(\'%s%s-%s-%s-%s-%s%s%s\', str_split(bin2hex($data), 4));\n    }\n\n// Function to generate a secure random file name\n    function generateRandomFileName($length) {\n        return bin2hex(random_bytes($length / 2));\n    }\n\n// Function to generate a secure random string\n    function generateRandomString($length) {\n        return bin2hex(random_bytes($length / 2));\n    }\n\n// Function to encrypt data\n    function encryptData($data, $config) {\n        $iv = random_bytes($config[\'encryption\'][\'iv_length\']); // Generate a secure random IV\n        $encryptedData = openssl_encrypt($data, $config[\'encryption\'][\'algorithm\'], $config[\'encryption\'][\'key\'], 0, $iv);\n        return base64_encode($encryptedData . \'::\' . $iv);\n    }\n\n// Function to decrypt data\n    function decryptData($data, $config) {\n        list($encryptedData, $iv) = explode(\'::\', base64_decode($data), 2);\n        return openssl_decrypt($encryptedData, $config[\'encryption\'][\'algorithm\'], $config[\'encryption\'][\'key\'], 0, $iv);\n    }\n\n// Function to send email notification\n    function sendEmailNotification($to, $subject, $body) {\n        global $emailHost, $emailUsername, $emailPassword, $emailFrom, $emailFromName;\n\n        $mail = new PHPMailer(true);\n        try {\n            // Server settings\n            $mail->isSMTP();\n            $mail->Host = $emailHost;\n            $mail->SMTPAuth = true;\n            $mail->Username = $emailUsername;\n            $mail->Password = $emailPassword;\n            $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;\n            $mail->Port = 587;\n\n            // Recipients\n            $mail->setFrom($emailFrom, $emailFromName);\n            $mail->addAddress($to);\n\n            // Content\n            $mail->isHTML(true);\n            $mail->Subject = $subject;\n            $mail->Body    = $body;\n\n            $mail->send();\n            return true;\n        } catch (Exception $e) {\n            return false;\n        }\n    }\n\n// Function to handle user signup\n    function signup($username, $password, $email, $conn, $config) {\n        // Sanitize input\n        $username = sanitizeInput($username);\n        $password = sanitizeInput($password);\n        $email = sanitizeInput($email);\n\n        // Validate password\n        if (!validatePassword($password)) {\n            return "Password must be at least 12 characters long after combining multiple spaces.";\n        }\n\n        // Hash the password with a randomly generated salt\n        $hashedPassword = password_hash($password, $config[\'hashing\'][\'algorithm\'], $config[\'hashing\'][\'options\']);\n\n        // Encrypt email\n        $encryptedEmail = encryptData($email, $config);\n\n        // Generate TOTP secret\n        $totp = TOTP::create();\n        $secret = $totp->getSecret();\n\n        // Prepare and bind\n        $stmt = $conn->prepare("INSERT INTO users (username, password, email, totp_secret) VALUES (?, ?, ?, ?)");\n        $stmt->bind_param("ssss", $username, $hashedPassword, $encryptedEmail, $secret);\n\n        // Execute the statement\n        if ($stmt->execute()) {\n            // Send notification email\n            $subject = "Signup Successful";\n            $body = "Dear $username,<br><br>Your account has been successfully created.<br><br>Regards,<br>Your App Name";\n            sendEmailNotification($email, $subject, $body);\n\n            // Display QR code for TOTP\n            $qrCodeUrl = $totp->getProvisioningUri();\n            echo "<p>Scan this QR code with your authenticator app:</p>";\n            echo "<img src=\'https://api.qrserver.com/v1/create-qr-code/?data=" . urlencode($qrCodeUrl) . "\'>";\n\n            return "Signup successful!";\n        } else {\n            return "Error: " . $stmt->error;\n        }\n\n        // Close the statement\n        $stmt->close();\n    }\n\n// Function to handle password change\n    function changePassword($username, $newPassword, $conn, $config) {\n        // Sanitize input\n        $username = sanitizeInput($username);\n        $newPassword = sanitizeInput($newPassword);\n\n        // Validate new password\n        if (!validatePassword($newPassword)) {\n            return "New password must be at least 12 characters long after combining multiple spaces.";\n        }\n\n        // Hash the new password with a randomly generated salt\n        $hashedNewPassword = password_hash($newPassword, $config[\'hashing\'][\'algorithm\'], $config[\'hashing\'][\'options\']);\n\n        // Prepare and bind\n        $stmt = $conn->prepare("UPDATE users SET password = ? WHERE username = ?");\n        $stmt->bind_param("ss", $hashedNewPassword, $username);\n\n        // Execute the statement\n        if ($stmt->execute()) {\n            // Get user\'s encrypted email\n            $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");\n            $stmt->bind_param("s", $username);\n            $stmt->execute();\n            $stmt->bind_result($encryptedEmail);\n            $stmt->fetch();\n            $stmt->close();\n\n            // Decrypt email\n            $email = decryptData($encryptedEmail, $config);\n\n            // Send notification email\n            $subject = "Password Changed Successfully";\n            $body = "Dear $username,<br><br>Your password has been successfully changed.<br><br>Regards,<br>Your App Name";\n            sendEmailNotification($email, $subject, $body);\n\n            return "Password changed successfully!";\n        } else {\n            return "Error: " . $stmt->error;\n        }\n\n        // Close the statement\n        $stmt->close();\n    }\n\n// Function to handle unknown login notification\n    function notifyUnknownLogin($username, $conn, $config) {\n        // Sanitize input\n        $username = sanitizeInput($username);\n\n        // Get user\'s encrypted email\n        $stmt = $conn->prepare("SELECT email FROM users WHERE username = ?");\n        $stmt->bind_param("s", $username);\n        $stmt->execute();\n        $stmt->bind_result($encryptedEmail);\n        $stmt->fetch();\n        $stmt->close();\n\n        // Decrypt email\n        $email = decryptData($encryptedEmail, $config);\n\n        // Send notification email\n        $subject = "Unknown Login Attempt";\n        $body = "Dear $username,<br><br>We detected a login attempt from an unknown location.<br><br>Regards,<br>Your App Name";\n        sendEmailNotification($email, $subject, $body);\n\n        return "Unknown login notification sent!";\n    }\n\n// Function to verify TOTP code\n    function verifyTotp($username, $totpCode, $conn) {\n        // Get user\'s TOTP secret\n        $stmt = $conn->prepare("SELECT totp_secret FROM users WHERE username = ?");\n        $stmt->bind_param("s", $username);\n        $stmt->execute();\n        $stmt->bind_result($secret);\n        $stmt->fetch();\n        $stmt->close();\n\n        // Verify the TOTP code\n        $totp = TOTP::create($secret);\n        return $totp->verify($totpCode);\n    }\n\n// Function to handle user login\n    function login($username, $password, $totpCode, $conn, $config) {\n        // Sanitize input\n        $username = sanitizeInput($username);\n        $password = sanitizeInput($password);\n\n        // Prepare and bind\n        $stmt = $conn->prepare("SELECT password, totp_secret FROM users WHERE username = ?");\n        $stmt->bind_param("s", $username);\n        $stmt->execute();\n        $stmt->bind_result($hashedPassword, $secret);\n        $stmt->fetch();\n        $stmt->close();\n\n        // Verify password\n        if (password_verify($password, $hashedPassword)) {\n            // Verify TOTP code\n            $totp = TOTP::create($secret);\n            if ($totp->verify($totpCode)) {\n                return "Login successful!";\n            } else {\n                notifyUnknownLogin($username, $conn, $config);\n                return "Invalid TOTP code.";\n            }\n        } else {\n            return "Invalid username or password.";\n        }\n    }\n}'}

def get_file_embeddings(file_name, file_content):
    """
    Generates embeddings for the contents of a given file.
    
    Args:
        file_content (str): content of file.
        file_name (str): name of file.
    
    Returns:
        numpy.ndarray: The embedding vector or None if an error occurs.
    """
    try:
        ret = model.encode(file_content)
        return ret
    except Exception as e:
        print(f"Error in embedding file: {file_name} - {e}")
        return None

# Main script execution
def build_index(files):
    print(f"Number of files found: {len(files)}")

    embeddings_dict = {}  # Dictionary to store embeddings with file paths
    index_map = {}  # Dictionary to map index to file paths
    i = 0  # Counter for processed files

    # Process each file to generate embeddings
    for file_name, file_content in files.items():
        e = get_file_embeddings(file_name, file_content)
        if e is None:
            continue
        embeddings_dict[file_name] = e
        index_map[i] = file_name
        i += 1
        if i % 100 == 0:
            print(f"Number of files processed: {i}")

    # Get the embedding dimension from the model
    embedding_dim = model.get_sentence_embedding_dimension()

    # Create an Annoy index with the appropriate dimensions and distance metric
    t = AnnoyIndex(embedding_dim, 'angular')

    # Add embeddings to the Annoy index
    for idx, (file, embedding) in enumerate(embeddings_dict.items()):
        t.add_item(idx, embedding)

    # Build the Annoy index
    t.build(len(files))

    # Save the Annoy index to a file
    index_filename = name + "_mpnet.ann"
    t.save(index_filename)

    # Save the index-to-filepath mapping to a text file
    with open('index_map_' + name + '.txt', 'w') as f:
        for idx, path in index_map.items():
            f.write(f'{idx}\t{path}\n')

    # Output the results
    print("Index created: " + index_filename)
    print("Number of files indexed: " + str(len(embeddings_dict)))

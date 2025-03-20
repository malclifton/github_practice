<?php
if ($_SERVER["REQUEST_METHOD"] === "POST") {

    $email = trim($_POST["email"] ?? '');
    $password = trim($_POST["password"] ?? '');

    if (empty($email) || empty($password)) {
        echo json_encode(["success" => false, "message" => "Email and password are required."]);
        exit;
    }
    // Database credentials
    $host = "localhost";
    $user = "mclifton6";
    $pass = "mclifton6";
    $dbname = "mclifton6";

    // Establish database connection
    $conn = new mysqli($host, $user, $pass, $dbname);
    if ($conn->connect_error) {
        echo json_encode(["success" => false, "message" => "Database connection failed."]);
        exit;
    }

    // Query to fetch user data
    $stmt = $conn->prepare("SELECT password FROM users WHERE email = ?");
    if (!$stmt) {
        echo json_encode(["success" => false, "message" => "Database query error."]);
        $conn->close();
        exit;
    }

    $stmt->bind_param("s", $email);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($user = $result->fetch_assoc()) {
        if (password_verify($password, $user["password"])) {
            // Start the session and set session variables --
            session_start();
            $_SESSION['logged_in'] = true;
            $_SESSION['email'] = $email;

            //   header("Location: ./"); will redirect to dashboard later on
            $conn->close();
            exit;
        } else {
            echo json_encode(["success" => false, "message" => "Invalid email or password."]);
        }
    } else {
        echo json_encode(["success" => false, "message" => "Invalid email or password."]);
    }

    $stmt->close();
    $conn->close();
}

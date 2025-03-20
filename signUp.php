<?php

// Form data
$fullName = trim($_POST["fullName"]);
$email = trim($_POST["email"]);
$password = $_POST["password"];
$phoneNumber = trim($_POST["phoneNumber"]);
$role = isset($_POST["owner"]) ? "Owner" : (isset($_POST["sitter"]) ? "Sitter" : "User");

// Validate inputs
if (empty($fullName)) {
    die("Full name required");
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("Valid email address required");
}
if (strlen($password) < 6) {
    die("Password must be at least 6 characters");
}
if (!preg_match("/[a-zA-Z]/", $password)) {
    die("Password must contain at least one letter");
}
if (!preg_match("/\d/", $password)) {
    die("Password must contain at least one number");
}

// Password Hash
$password_hash = password_hash($password, PASSWORD_DEFAULT);

// Database credentials
$host = "localhost";
$user = "mclifton6";
$pass = "mclifton6";
$dbname = "mclifton6";

// Connect to database
$conn = new mysqli($host, $user, $pass, $dbname);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Prepare SQL statement 
$stmt = $conn->prepare("INSERT INTO users (fullName, email, password_hash, phone, role) VALUES (?, ?, ?, ?, ?)");
$stmt->bind_param("sssss", $fullName, $email, $password_hash, $phoneNumber, $role);

// Execute
if ($stmt->execute()) {
    header("Location: ./signIn.html");  // Redirect to login page
    $stmt->close();
    $conn->close();
    exit;
} else {
    die("Error: " . $stmt->error);
}

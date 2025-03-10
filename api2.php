<?php
require 'vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

$secretKey = 'your_secret_key';
$host = 'localhost';
$db_name = 'your_db';
$username = 'root';
$password = '';

$conn = new PDO("mysql:host=$host;dbname=$db_name;charset=utf8mb4", $username, $password);
$conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Получение входящих данных
$requestPayload = json_decode(file_get_contents('php://input'), true);
$action = $requestPayload['action'] ?? null;

switch ($action) {
    case 'login':
        $email = $requestPayload['email'] ?? '';
        $password = $requestPayload['password'] ?? '';

        // Ваш код для проверки пользовтеля и получения хешированного пароля
        $stmt = $conn->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if ($user && password_verify($password, $user['password'])) {
            $jwt = JWT::encode(['email' => $email, 'exp' => time() + (90 * 24 * 60 * 60)], $secretKey, 'HS256');
            http_response_code(200);
            echo json_encode(['jwt' => $jwt]);
        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Authentication failed']);
        }
        break;

    case 'register':
        $email = $requestPayload['email'] ?? '';
        $password = password_hash($requestPayload['password'] ?? '', PASSWORD_BCRYPT);
        $firstName = $requestPayload['firstName'] ?? '';
        $secondName = $requestPayload['secondName'] ?? '';
        $surname = $requestPayload['surname'] ?? '';
        $class = $requestPayload['class'] ?? '';
        $parralel = $requestPayload['parralel'] ?? '';

        $stmt = $conn->prepare("INSERT INTO users (email, password, firstName, secondName, surname, class, parralel) VALUES (?, ?, ?, ?, ?, ?, ?)");
        if($stmt->execute([$email, $password, $firstName, $secondName, $surname, $class, $parralel])){
            http_response_code(200);
        } else {
            http_response_code(400);
        }
        break;

    case 'getGradesSumary':
        $authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
        if (strpos($authorization, 'Bearer ') === 0) {
            $jwt = substr($authorization, 7);
            try {
                $decoded = JWT::decode($jwt, new Key($secretKey, 'HS256'));
                // Ваш код для получения оценок
                $stmt = $conn->prepare("SELECT subject, grade FROM grades WHERE user_email = ? LIMIT ?");
                $stmt->execute([$decoded->email, $requestPayload['quantity'] ?? 10]);
                $grades = $stmt->fetchAll(PDO::FETCH_ASSOC);
                http_response_code(200);
                echo json_encode($grades);
            } catch (Exception $e) {
                http_response_code(401);
                echo json_encode(['message' => 'Unauthorized']);
            }
        } else {
            http_response_code(401);
            echo json_encode(['message' => 'Unauthorized']);
        }
        break;

    default:
        http_response_code(400);
        echo json_encode(['message' => 'Invalid action']);
}
?>
<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);
header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

if ($_SERVER['REQUEST_METHOD'] == 'OPTIONS') {
    http_response_code(200);
    exit;
}

$secret_key = 'my_secret_key'; // секретный ключ для jwt токена :3

// функция для преобразования в base64url
function base64UrlEncode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

// генерация jwt токена
function generateJWT($payload, $secret) {
    $header = json_encode(['alg'=>'HS256','typ'=>'JWT']);
    $payload = json_encode($payload);
    $base64UrlHeader = base64UrlEncode($header);
    $base64UrlPayload = base64UrlEncode($payload);
    $signature = hash_hmac('sha256', $base64UrlHeader.'.'.$base64UrlPayload, $secret, true);
    $base64UrlSignature = base64UrlEncode($signature);
    return $base64UrlHeader.'.'.$base64UrlPayload.'.'.$base64UrlSignature;
}

// проверка jwt токена
function verifyJWT($jwt, $secret) {
    $parts = explode('.', $jwt);
    if(count($parts) != 3) return false;
    list($headerB64, $payloadB64, $signatureProvided) = $parts;
    $signature = hash_hmac('sha256', $headerB64.'.'.$payloadB64, $secret, true);
    $base64UrlSignature = base64UrlEncode($signature);
    if($base64UrlSignature !== $signatureProvided) return false;
    $payload = json_decode(base64_decode(strtr($payloadB64, '-_', '+/')), true);
    if(!$payload) return false;
    if(isset($payload['exp']) && $payload['exp'] < time()) return false;
    return $payload;
}

// подключаемся к базе данных sqlite3
$db = new SQLite3('database.db');
// защита от sql инъекций
$userId = $_GET['id'];
$stmt = $db->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindValue(':id', $userId, SQLITE3_INTEGER);
$result = $stmt->execute();

// создаем таблицы если их нет - изначально бд пустые
$db->exec("CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    secondName TEXT,
    firstName TEXT,
    surname TEXT,
    class TEXT,
    parralel TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    subject TEXT,
    grade INTEGER
)");

$db->exec("CREATE TABLE IF NOT EXISTS homework (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    subject TEXT,
    task TEXT,
    dueDate TEXT
)");

$db->exec("CREATE TABLE IF NOT EXISTS news (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    date TEXT,
    content TEXT
)");

// получаем тело запроса (ожидаем json)
$input = json_decode(file_get_contents("php://input"), true);
if(!$input){
    http_response_code(400);
    echo json_encode(["error" => "неправильный ввод"]);
    exit;
}

// получаем заголовок авторизации если есть
$authHeader = null;
if(isset($_SERVER['HTTP_AUTHORIZATION'])) {
    $authHeader = $_SERVER['HTTP_AUTHORIZATION'];
} elseif(isset($_SERVER['Authorization'])){
    $authHeader = $_SERVER['Authorization'];
}

// получаем action
$action = isset($input['action']) ? $input['action'] : null;
if(!$action){
    http_response_code(400);
    echo json_encode(["error" => "не указан action"]);
    exit;
}

// функция для получения данных пользователя из jwt
function getUserFromJWT($secret) {
    global $authHeader;
    if(!$authHeader) return null;
    if(strpos($authHeader, 'Bearer ') !== 0) return null;
    $jwt = trim(str_replace('Bearer ', '', $authHeader));
    $payload = verifyJWT($jwt, $secret);
    if($payload === false) return null;
    return $payload;
}

switch($action){

    case 'login':
        if(!isset($input['email']) || !isset($input['password'])){
            http_response_code(400);
            echo json_encode(["error" => "email и password обязательны"]);
            exit;
        }
        $email = $input['email'];
        $password = $input['password'];
        $stmt = $db->prepare("SELECT * FROM users WHERE email = :email");
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);
        if(!$user){
            http_response_code(401);
            echo json_encode(["error" => "неверные данные"]);
            exit;
        }
        if(!password_verify($password, $user['password'])){
            http_response_code(401);
            echo json_encode(["error" => "неверные данные"]);
            exit;
        }
        $exp = time() + 7776000; // 3 месяца
        $token = generateJWT(['user_id'=>$user['id'],'exp'=>$exp], $secret_key);
        echo json_encode(["jwt" => $token]);
        exit;
    break;

    case 'register':
        $required = ['email','password','secondName','firstName','surname','class','parralel'];
        foreach($required as $field){
            if(!isset($input[$field])){
                http_response_code(400);
                echo json_encode(["error" => "не хватает поля $field"]);
                exit;
            }
        }
        $email = $input['email'];
        $password = password_hash($input['password'], PASSWORD_DEFAULT);
        $secondName = $input['secondName'];
        $firstName = $input['firstName'];
        $surname = $input['surname'];
        $class = $input['class'];
        $parralel = $input['parralel'];
        $stmt = $db->prepare("INSERT INTO users (email, password, secondName, firstName, surname, class, parralel)
            VALUES (:email, :password, :secondName, :firstName, :surname, :class, :parralel)");
        $stmt->bindValue(':email', $email, SQLITE3_TEXT);
        $stmt->bindValue(':password', $password, SQLITE3_TEXT);
        $stmt->bindValue(':secondName', $secondName, SQLITE3_TEXT);
        $stmt->bindValue(':firstName', $firstName, SQLITE3_TEXT);
        $stmt->bindValue(':surname', $surname, SQLITE3_TEXT);
        $stmt->bindValue(':class', $class, SQLITE3_TEXT);
        $stmt->bindValue(':parralel', $parralel, SQLITE3_TEXT);
        $result = $stmt->execute();
        if($result){
            http_response_code(200);
            echo json_encode(new stdClass());
        } else {
            http_response_code(500);
            echo json_encode(["error" => "регистрация не удалась"]);
        }
        exit;
    break;

    case 'getGradesSumary':
        $payload = getUserFromJWT($secret_key);
        if(!$payload){
            http_response_code(401);
            echo json_encode(["error" => "нет доступа"]);
            exit;
        }
        $user_id = $payload['user_id'];
        $quantity = isset($input['quantity']) ? (int)$input['quantity'] : 0;
        $stmt = $db->prepare("SELECT subject, grade FROM grades WHERE user_id = :user_id ORDER BY id DESC LIMIT :quantity");
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(':quantity', $quantity, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $grades = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $subject = $row['subject'];
            $grade = (int)$row['grade'];
            if(!isset($grades[$subject])){
                $grades[$subject] = [];
            }
            $grades[$subject][] = $grade;
        }
        $summary = [];
        foreach($grades as $subject => $gradesArr){
            $avg = round(array_sum($gradesArr)/count($gradesArr));
            $summary[] = ['subject'=>$subject, 'grade'=>$avg];
        }
        echo json_encode($summary);
        exit;
    break;

    case 'getGrades':
        $payload = getUserFromJWT($secret_key);
        if(!$payload){
            http_response_code(401);
            echo json_encode(["error" => "нет доступа"]);
            exit;
        }
        $user_id = $payload['user_id'];
        $stmt = $db->prepare("SELECT subject, grade FROM grades WHERE user_id = :user_id");
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $grades = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $subject = $row['subject'];
            if(!isset($grades[$subject])) $grades[$subject] = [];
            $grades[$subject][] = (int)$row['grade'];
        }
        echo json_encode($grades);
        exit;
    break;

    case 'getHomeworkSummary':
        $payload = getUserFromJWT($secret_key);
        if(!$payload){
            http_response_code(401);
            echo json_encode(["error" => "нет доступа"]);
            exit;
        }
        $user_id = $payload['user_id'];
        $quantity = isset($input['quantity']) ? (int)$input['quantity'] : 0;
        $stmt = $db->prepare("SELECT subject, task, dueDate FROM homework WHERE user_id = :user_id ORDER BY id DESC LIMIT :quantity");
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(':quantity', $quantity, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $summary = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $summary[] = ['subject'=>$row['subject'], 'task'=>$row['task'], 'dueDate'=>$row['dueDate']];
        }
        echo json_encode($summary);
        exit;
    break;

    case 'getDetailedHomework':
        $payload = getUserFromJWT($secret_key);
        if(!$payload){
            http_response_code(401);
            echo json_encode(["error" => "нет доступа"]);
            exit;
        }
        $user_id = $payload['user_id'];
        $stmt = $db->prepare("SELECT subject, task, dueDate FROM homework WHERE user_id = :user_id ORDER BY subject");
        $stmt->bindValue(':user_id', $user_id, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $detailed = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $subject = $row['subject'];
            if(!isset($detailed[$subject])) $detailed[$subject] = [];
            $detailed[$subject][] = ['task'=>$row['task'], 'dueDate'=>$row['dueDate']];
        }
        $output = [];
        foreach($detailed as $subject=>$tasks){
            $output[] = ['subject'=>$subject, 'tasks'=>$tasks];
        }
        echo json_encode($output);
        exit;
    break;

    case 'news':
        $result = $db->query("SELECT title, date FROM news ORDER BY date DESC");
        $news = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $news[] = ['title'=>$row['title'], 'date'=>$row['date']];
        }
        echo json_encode($news);
        exit;
    break;

    case 'newsDetailed':
        $result = $db->query("SELECT title, date, content FROM news ORDER BY date DESC");
        $newsDetailed = [];
        while($row = $result->fetchArray(SQLITE3_ASSOC)){
            $newsDetailed[] = ['title'=>$row['title'], 'date'=>$row['date'], 'content'=>$row['content']];
        }
        echo json_encode($newsDetailed);
        exit;
    break;

    default:
        http_response_code(400);
        echo json_encode(["error" => "action неизвестен"]);
        exit;
    break;
}
?>

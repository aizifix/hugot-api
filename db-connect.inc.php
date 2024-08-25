<?php



$servername = "localhost";
$username = "root";
$password = "";
$dbname = "db_hugot_app";

try {
    $conn = new PDO("mysql:host=$servername;dbname=$dbname", $username, $password);
    $conn->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

}catch (PDOException $e){
    echo json_encode(['error' => $e->getMessage()]);
    exit;
}

?>

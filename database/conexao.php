<?php

$host = '69.62.98.150';
$db   = 'rsrdev';
$user = 'rsrdev';
$pass = 'Silvia1225@';
$charset = 'utf8mb4';

$dsn = "mysql:host=$host;dbname=$db;charset=$charset";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $pass, $options);
} catch (PDOException $e) {
    // Em produção, evite exibir detalhes do erro para o usuário final
    die('Erro na conexão com o banco de dados: ' . $e->getMessage());
}

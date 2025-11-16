<?php

require __DIR__ . '/database/conexao.php';

try {
    echo "Conexao com o banco realizada com sucesso!" . PHP_EOL;

    $stmt = $pdo->query('SELECT 1');
    $resultado = $stmt->fetch();
    echo "Teste de consulta executado com sucesso:" . PHP_EOL;
    var_dump($resultado);
} catch (PDOException $e) {
    echo "Falha ao executar teste no banco: " . $e->getMessage() . PHP_EOL;
}
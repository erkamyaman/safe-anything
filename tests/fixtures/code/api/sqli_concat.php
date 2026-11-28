<?php
DB::select('SELECT * FROM users WHERE id = \'' . $id . '\'');
$stmt = $pdo->prepare("SELECT * FROM users WHERE name = '" . $name . "'");
$conn->executeQuery('SELECT * FROM users WHERE id = \'' . (string)$id . '\'');
$rows = DB::table('users')->whereRaw('id = \'' . $id . '\'')->get();
$rows = $conn->createQueryBuilder()->select('*')->from('users')->where('id = \'' . $id . '\'')->executeQuery();
$q = "SELECT * FROM users WHERE name = \"$name\"";
DB::select('SELECT * FROM users ORDER BY ' . $sort);
DB::select('SELECT * FROM users WHERE id = ?', [$id]);
$stmt = $pdo->prepare('SELECT * FROM users WHERE name = :name');
$rows = DB::table('users')->where('id', $id)->get();
$rows = $conn->createQueryBuilder()->select('*')->from('users')->where('id = :id')->setParameter('id', $id);
DB::select('SELECT * FROM users WHERE id = ' . (int)$id);
DB::select('SELECT * FROM users WHERE id = ' . intval($id));
$conn->executeQuery('SELECT * FROM users WHERE ' . $conn->quoteIdentifier($col) . ' = 1');
$rows = DB::table('users')->where('name', 'like', '%' . $term . '%')->get();
$r = mysqli_query($db, "SELECT * FROM users WHERE name = '" . mysqli_real_escape_string($db, $name) . "'");
$sql = 'SELECT * FROM users WHERE name = ' . $pdo->quote($name);

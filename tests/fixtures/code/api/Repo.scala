val a = s"SELECT id FROM users WHERE id = $id"
val b = s"SELECT id FROM users WHERE id = ${user.id}"
val c = "SELECT id FROM users WHERE id = " + id
val d = s"Selected $n users from the list"
val e = sql"SELECT id FROM users WHERE id = $id"

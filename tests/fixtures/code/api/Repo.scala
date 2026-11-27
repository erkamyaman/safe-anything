val a = s"SELECT id FROM users WHERE id = $id"
val b = s"SELECT id FROM users WHERE id = ${user.id}"
val c = s"Selected $n users from the list"
val d = sql"SELECT id FROM users WHERE id = $id"
val e = "SELECT id FROM users WHERE id = $id"
val f = "SELECT id FROM users WHERE id = " + id

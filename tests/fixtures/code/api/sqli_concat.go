stmt, err := db.Prepare("SELECT id, name FROM users WHERE name = '" + name + "'")
err := gormDB.Raw("SELECT id, name FROM users WHERE name = '" + name + "'").Scan(&u).Error
q := "SELECT * FROM users WHERE id = '" + id + "'"
err := gormDB.Where("name = '" + name + "'").First(&u).Error
stmt, err := db.Prepare("SELECT id, name FROM users WHERE id = $1")
err := gormDB.Raw("SELECT id, name FROM users WHERE id = ?", id).Scan(&u).Error
err := gormDB.Where("name = ?", name).First(&u).Error
q := fmt.Sprintf("SELECT * FROM users WHERE id = %d", id)
q := fmt.Sprintf(`SELECT * FROM "%s"`, strings.ReplaceAll(table, `"`, `""`))
q := fmt.Sprintf("SELECT * FROM %s", pq.QuoteIdentifier(table))
q := "SELECT * FROM users WHERE id = " + strconv.Itoa(id)
rows, err := db.Query("SELECT * FROM users WHERE id = $1", id)

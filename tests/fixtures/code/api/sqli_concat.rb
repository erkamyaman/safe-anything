User.find_by_sql("SELECT * FROM users WHERE id = '" + id + "'")
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = '" + params[:id] + "'")
DB["SELECT * FROM users WHERE id = '" + id + "'"].all
DB.fetch('SELECT * FROM users WHERE name = \'' + name + '\'').all
User.where("name = '" + name + "'")
DB[:users].with_sql("SELECT * FROM users WHERE id = '" + id + "'").all
User.find_by_sql(["SELECT * FROM users WHERE id = ?", id])
DB.fetch("SELECT * FROM users WHERE id = ?", id).all
User.where(id: id)
ActiveRecord::Base.connection.execute("SELECT * FROM users ORDER BY " + ActiveRecord::Base.connection.quote_column_name(col))
DB["SELECT * FROM users ORDER BY " + DB.quote_identifier(col)].all
ActiveRecord::Base.connection.execute("SELECT * FROM users WHERE id = " + id.to_i.to_s)
DB.execute("SELECT * FROM " + (name =~ /\A\w+\z/ ? name : "users"))
User.where("name = ?", name)

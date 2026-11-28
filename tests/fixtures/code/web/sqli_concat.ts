await this.dataSource.query("SELECT * FROM users WHERE name = '" + name + "'");
const rows = await repo.createQueryBuilder("u").where("u.email = '" + dto.email + "'").getRawMany();
await db.run(sql.raw("SELECT * FROM users WHERE id = '" + id + "'"));
await this.dataSource.query("SELECT * FROM users WHERE name = $1", [name]);
const found = await repo.createQueryBuilder("u").where("u.email = :email", { email: dto.email }).getRawMany();
await db.run(sql`SELECT * FROM users WHERE id = ${id}`);
const byId: User[] = await db.query("SELECT * FROM users WHERE id = " + Number(raw));

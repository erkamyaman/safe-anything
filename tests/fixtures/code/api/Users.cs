var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + id, conn);
var cmd2 = new SqlCommand($"SELECT * FROM Users WHERE Id = {id}", conn);
var f = new BinaryFormatter();
var cmd3 = new SqlCommand("SELECT Id\nFROM Users WHERE Id = " + id, conn);
var msg = "selected\n" + n + " files from " + dir;

import sqlite3

def get_user(user_id):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
    return cursor.fetchone()
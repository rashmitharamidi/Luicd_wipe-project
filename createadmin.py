from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import psycopg2.extras 
DB_CONFIG = {
    'dbname': 'piidb',
    'user': 'postgres',
    'password': '5432',
    'host': 'localhost'
}
conn = psycopg2.connect(**DB_CONFIG)
cur = conn.cursor()
admin_password = generate_password_hash("ranjith")
cur.execute(
    "INSERT INTO users (username, password, role, status) VALUES (%s, %s, %s, %s)",
    ("ranjith", admin_password, "admin", "approved")
)
conn.commit()
conn.close()
import sqlite3

path = r"c:\Users\Acer\Documents\Software Engineering\TrojanMate\trojanmate.db"
conn = sqlite3.connect(path)
cur = conn.cursor()
print('TABLES')
for row in cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"):
    print(row[0])
print('\nSCHEMA')
for name in ['users','tutor_profiles','messages','notifications','bookings','availability','subjects','tutor_subjects','feedback']:
    print(f'-- {name} --')
    for row in cur.execute(f'PRAGMA table_info({name})'):
        print(row)
    print()
print('USER_ROLES')
for row in cur.execute('SELECT id, name, email, role FROM users ORDER BY id LIMIT 20'):
    print(row)
print('MESSAGE_SAMPLE')
for row in cur.execute('SELECT * FROM messages ORDER BY id DESC LIMIT 5'):
    print(row)
conn.close()

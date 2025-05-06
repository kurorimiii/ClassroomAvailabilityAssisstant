from flask import Flask, render_template, request, redirect, session
import sqlite3
from datetime import datetime
from pytz import timezone
from werkzeug.security import generate_password_hash, check_password_hash

class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'user'))
            )''')
            cursor.execute('''CREATE TABLE IF NOT EXISTS RoomSchedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                day TEXT NOT NULL,
                start_time TEXT NOT NULL,
                end_time TEXT NOT NULL,
                subject TEXT NOT NULL,
                section TEXT NOT NULL,
                room TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'available',
                manual_override TEXT DEFAULT NULL
            )''')
            cursor.execute("SELECT COUNT(*) FROM users")
            if cursor.fetchone()[0] == 0:
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                               ("admin", generate_password_hash('admin123'), 'admin'))
                cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                               ("guest", generate_password_hash('guest123'), 'user'))
            conn.commit()

    def execute(self, query, params=(), fetch=False, fetchone=False):
        with sqlite3.connect(self.db_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            if fetchone:
                return cursor.fetchone()
            if fetch:
                return cursor.fetchall()
            return None

class UserManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def register(self, username, password, role='user'):
        if len(username) < 4:
            raise ValueError("Username must be at least 4 characters long.")
        if len(password) < 6:
            raise ValueError("Password must be at least 6 characters long.")
        hashed = generate_password_hash(password)
        return self.db.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                               (username, hashed, role))

    def authenticate(self, username, password):
        user = self.db.execute("SELECT id, username, role, password FROM users WHERE username = ?",
                               (username,), fetchone=True)
        if user and check_password_hash(user[3], password):
            return {'id': user[0], 'username': user[1], 'role': user[2]}
        return None

    def get_all_users(self):
        return self.db.execute("SELECT id, username, role FROM users ORDER BY username ASC", fetch=True)

    def remove_user(self, user_id):
        return self.db.execute("DELETE FROM users WHERE id = ?", (user_id,))

class ScheduleManager:
    def __init__(self, db: DatabaseManager):
        self.db = db

    def current_day_time(self):
        now = datetime.now(timezone('Asia/Manila'))
        return now.strftime('%A'), now.strftime('%H:%M')

    def get_schedule(self, day_filter=None, search=None):
        day, now_time = self.current_day_time()
        current_time_obj = datetime.strptime(now_time, '%H:%M')

        query = "SELECT * FROM RoomSchedule WHERE 1=1"
        params = []
        if day_filter:
            query += " AND day = ?"
            params.append(day_filter)
        if search:
            query += " AND (subject LIKE ? OR section LIKE ? OR room LIKE ?)"
            like = f"%{search}%"
            params.extend([like] * 3)

        rows = self.db.execute(query, params, fetch=True)
        schedule = []
        room_in_use = set()

        for row in rows:
            sched_day, start, end, room, override = row[1], row[2], row[3], row[6], row[8]
            try:
                start_obj = datetime.strptime(start, '%H:%M')
                end_obj = datetime.strptime(end, '%H:%M')
            except ValueError:
                continue
            if sched_day == day and start_obj <= current_time_obj <= end_obj:
                room_in_use.add(room)

        for row in rows:
            id, sched_day, start, end, subject, section, room, status, override = row
            try:
                datetime.strptime(start, '%H:%M')
                datetime.strptime(end, '%H:%M')
            except ValueError:
                continue
            if room in room_in_use:
                status = "Available (Manual)" if override == "available" else \
                         "Occupied (Manual)" if override == "occupied" else "Occupied (Auto)"
            else:
                status = "Occupied (Manual)" if override == "occupied" else \
                         "Available (Manual)" if override == "available" else "Available (Auto)"
            schedule.append({
                'id': id, 'day': sched_day, 'start_time': start, 'end_time': end,
                'subject': subject, 'section': section, 'room': room, 'status': status
            })
        schedule.sort(key=lambda x: ('Available' in x['status'], x['status'] != 'Available (Auto)'), reverse=True)
        return schedule

    def add_schedule(self, day, start_time, end_time, subject, section, room):
        return self.db.execute(
            '''INSERT INTO RoomSchedule (day, start_time, end_time, subject, section, room, status) 
               VALUES (?, ?, ?, ?, ?, ?, ?)''',
            (day, start_time, end_time, subject, section, room, "available")
        )

    def override_status(self, schedule_id, action):
        override_value = None if action == 'auto' else action
        row = self.db.execute("SELECT room, day FROM RoomSchedule WHERE id = ?", (schedule_id,), fetchone=True)
        if row:
            room, day = row
            self.db.execute("UPDATE RoomSchedule SET manual_override = ? WHERE room = ? AND day = ?",
                            (override_value, room, day))

    def delete_schedule(self, schedule_id):
        return self.db.execute("DELETE FROM RoomSchedule WHERE id = ?", (schedule_id,))

class RoomScheduleApp:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = 'supersecretkey'
        self.db = DatabaseManager('room_schedule.db')
        self.user_mgr = UserManager(self.db)
        self.sched_mgr = ScheduleManager(self.db)
        self._routes()

    def _routes(self):
        app = self.app

        @app.route('/')
        def index():
            if 'username' in session:
                schedule = self.sched_mgr.get_schedule(
                    request.args.get('day'), request.args.get('search'))
                return render_template('index.html', schedule=schedule, role=session['role'])
            return render_template('home.html')

        @app.route('/login', methods=['GET', 'POST'])
        def login():
            if request.method == 'POST':
                user = self.user_mgr.authenticate(
                    request.form['username'], request.form['password'])
                if user:
                    session.update(user)  # This now includes 'id', 'username', 'role'
                    session['user_id'] = user['id']  # Make sure user_id is added to session
                    return redirect('/')
                return render_template('login.html', error="Invalid credentials")
            return render_template('login.html')

        @app.route('/logout')
        def logout():
            session.clear()
            return redirect('/')

        @app.route('/register', methods=['GET', 'POST'])
        def register():
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                if len(username) < 4:
                    return render_template('register.html', error="Username must be at least 4 characters long.")
                if len(password) < 6:
                    return render_template('register.html', error="Password must be at least 6 characters long.")
                try:
                    self.user_mgr.register(username, password)
                    return redirect('/login')
                except sqlite3.IntegrityError:
                    return render_template('register.html', error="Username already exists.")
            return render_template('register.html')

        @app.route('/add', methods=['GET', 'POST'])
        def add():
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            if request.method == 'POST':
                self.sched_mgr.add_schedule(
                    request.form['day'], request.form['start_time'],
                    request.form['end_time'], request.form['subject'],
                    request.form['section'], request.form['room']
                )
                return redirect('/')
            return render_template('add.html')

        @app.route('/add-admin', methods=['GET', 'POST'])
        def add_admin():
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            if request.method == 'POST':
                username = request.form['username']
                password = request.form['password']
                if len(username) < 4:
                    return render_template('add_admin.html', error="Username must be at least 4 characters long.")
                if len(password) < 6:
                    return render_template('add_admin.html', error="Password must be at least 6 characters long.")
                try:
                    self.user_mgr.register(username, password, 'admin')
                    return "New admin created successfully!"
                except sqlite3.IntegrityError:
                    return render_template('add_admin.html', error="Username already exists.")
            return render_template('add_admin.html')

        @app.route('/override/<int:schedule_id>/<action>')
        def override(schedule_id, action):
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            self.sched_mgr.override_status(schedule_id, action)
            return redirect('/')

        @app.route('/delete-schedule/<int:schedule_id>')
        def delete_schedule(schedule_id):
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            self.sched_mgr.delete_schedule(schedule_id)
            return redirect('/')

        @app.route('/remove_user_admin')
        def remove_user_admin():
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            users = self.user_mgr.get_all_users()
            return render_template('remove_user_admin.html', users=users)

        @app.route('/remove-user/<string:username>', methods=['POST'])
        def remove_user(username):
            if session.get('role') != 'admin':
                return "Unauthorized", 403
            if request.form['user_id'] == str(session['user_id']):
                return "You cannot remove yourself.", 400
            self.user_mgr.remove_user(request.form['user_id'])
            return redirect('/remove_user_admin')


# Entrypoint
app_instance = RoomScheduleApp()
app = app_instance.app

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)

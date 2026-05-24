from flask import Flask, request, jsonify, render_template, session
import database
import hashlib
import secrets

app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'weekly-flow-secured-key-998877'

# Initialize the database on startup
database.init_db()

# --- PASSWORD HASHING HELPERS ---

def generate_salt():
    return secrets.token_hex(16)

def hash_password(password, salt):
    pwd_bytes = password.encode('utf-8')
    salt_bytes = salt.encode('utf-8')
    h = hashlib.pbkdf2_hmac('sha256', pwd_bytes, salt_bytes, 100000)
    return h.hex()

@app.route('/')
def index():
    return render_template('index.html')

# --- AUTHENTICATION API ---

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
        
    username = data['username'].strip()
    password = data['password']
    
    if len(username) < 3:
        return jsonify({'error': 'Username must be at least 3 characters long'}), 400
    if len(password) < 4:
        return jsonify({'error': 'Password must be at least 4 characters long'}), 400

    conn = database.get_db_connection()
    try:
        # Check if user already exists
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user:
            return jsonify({'error': 'Username is already taken'}), 400
            
        salt = generate_salt()
        pwd_hash = hash_password(password, salt)
        
        cursor = conn.cursor()
        cursor.execute(
            'INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)',
            (username, pwd_hash, salt)
        )
        user_id = cursor.lastrowid
        conn.commit()
        
        # Log the user in immediately
        session['user_id'] = user_id
        session['username'] = username
        
        return jsonify({'id': user_id, 'username': username}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
        
    username = data['username'].strip()
    password = data['password']

    conn = database.get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    
    if not user:
        return jsonify({'error': 'Invalid username or password'}), 401
        
    # Verify hash
    computed_hash = hash_password(password, user['salt'])
    if computed_hash != user['password_hash']:
        return jsonify({'error': 'Invalid username or password'}), 401
        
    session['user_id'] = user['id']
    session['username'] = user['username']
    
    return jsonify({'id': user['id'], 'username': user['username']})

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/me', methods=['GET'])
def get_me():
    if 'user_id' in session:
        return jsonify({
            'logged_in': True,
            'id': session['user_id'],
            'username': session['username']
        })
    return jsonify({'logged_in': False})

# --- TASKS API (PROTECTED) ---

@app.route('/api/tasks', methods=['GET'])
def get_tasks():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = database.get_db_connection()
    tasks = conn.execute('SELECT * FROM tasks WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    
    task_list = []
    for t in tasks:
        task_list.append({
            'id': t['id'],
            'name': t['name'],
            'time': t['time'],
            'priority': t['priority'],
            'notes': t['notes'],
            'day': t['day'],
            'completed': bool(t['completed'])
        })
    return jsonify(task_list)

@app.route('/api/tasks', methods=['POST'])
def add_task():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json
    if not data or not data.get('name') or not data.get('day'):
        return jsonify({'error': 'Missing required fields: name and day'}), 400
        
    name = data['name']
    time = data.get('time', '')
    priority = data.get('priority', 'Medium')
    notes = data.get('notes', '')
    day = data['day']
    completed = 1 if data.get('completed', False) else 0
    
    if priority not in ('Low', 'Medium', 'High'):
        priority = 'Medium'
    if day not in ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'):
        return jsonify({'error': 'Invalid day of week'}), 400

    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO tasks (user_id, name, time, priority, notes, day, completed) VALUES (?, ?, ?, ?, ?, ?, ?)',
        (user_id, name, time, priority, notes, day, completed)
    )
    task_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'id': task_id,
        'name': name,
        'time': time,
        'priority': priority,
        'notes': notes,
        'day': day,
        'completed': bool(completed)
    }), 201

@app.route('/api/tasks/<int:task_id>', methods=['PUT'])
def update_task(task_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json
    if not data:
        return jsonify({'error': 'No data provided'}), 400
        
    conn = database.get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id)).fetchone()
    if not task:
        conn.close()
        return jsonify({'error': 'Task not found'}), 404
        
    # Build update dynamic query
    fields = []
    values = []
    
    if 'name' in data:
        fields.append('name = ?')
        values.append(data['name'])
    if 'time' in data:
        fields.append('time = ?')
        values.append(data['time'])
    if 'priority' in data:
        if data['priority'] in ('Low', 'Medium', 'High'):
            fields.append('priority = ?')
            values.append(data['priority'])
    if 'notes' in data:
        fields.append('notes = ?')
        values.append(data['notes'])
    if 'day' in data:
        if data['day'] in ('Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'):
            fields.append('day = ?')
            values.append(data['day'])
    if 'completed' in data:
        fields.append('completed = ?')
        values.append(1 if data['completed'] else 0)
        
    if not fields:
        conn.close()
        return jsonify({'error': 'No updates provided'}), 400
        
    values.extend([task_id, user_id])
    query = f"UPDATE tasks SET {', '.join(fields)} WHERE id = ? AND user_id = ?"
    
    conn.execute(query, values)
    conn.commit()
    
    # Fetch updated task
    updated = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id)).fetchone()
    conn.close()
    
    return jsonify({
        'id': updated['id'],
        'name': updated['name'],
        'time': updated['time'],
        'priority': updated['priority'],
        'notes': updated['notes'],
        'day': updated['day'],
        'completed': bool(updated['completed'])
    })

@app.route('/api/tasks/<int:task_id>', methods=['DELETE'])
def delete_task(task_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = database.get_db_connection()
    task = conn.execute('SELECT * FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id)).fetchone()
    if not task:
        conn.close()
        return jsonify({'error': 'Task not found'}), 404
        
    conn.execute('DELETE FROM tasks WHERE id = ? AND user_id = ?', (task_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

# --- GOALS API (PROTECTED) ---

@app.route('/api/goals', methods=['GET'])
def get_goals():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = database.get_db_connection()
    goals = conn.execute('SELECT * FROM goals WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    
    goal_list = []
    for g in goals:
        goal_list.append({
            'id': g['id'],
            'text': g['text'],
            'completed': bool(g['completed'])
        })
    return jsonify(goal_list)

@app.route('/api/goals', methods=['POST'])
def add_goal():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json
    if not data or not data.get('text'):
        return jsonify({'error': 'Missing required fields: text'}), 400
        
    text = data['text']
    completed = 1 if data.get('completed', False) else 0
    
    conn = database.get_db_connection()
    cursor = conn.cursor()
    cursor.execute('INSERT INTO goals (user_id, text, completed) VALUES (?, ?, ?)', (user_id, text, completed))
    goal_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return jsonify({
        'id': goal_id,
        'text': text,
        'completed': bool(completed)
    }), 201

@app.route('/api/goals/<int:goal_id>', methods=['PUT'])
def update_goal(goal_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.json
    if not data or 'completed' not in data:
        return jsonify({'error': 'Missing field: completed'}), 400
        
    conn = database.get_db_connection()
    goal = conn.execute('SELECT * FROM goals WHERE id = ? AND user_id = ?', (goal_id, user_id)).fetchone()
    if not goal:
        conn.close()
        return jsonify({'error': 'Goal not found'}), 404
        
    completed = 1 if data['completed'] else 0
    conn.execute('UPDATE goals SET completed = ? WHERE id = ? AND user_id = ?', (completed, goal_id, user_id))
    conn.commit()
    
    updated = conn.execute('SELECT * FROM goals WHERE id = ? AND user_id = ?', (goal_id, user_id)).fetchone()
    conn.close()
    
    return jsonify({
        'id': updated['id'],
        'text': updated['text'],
        'completed': bool(updated['completed'])
    })

@app.route('/api/goals/<int:goal_id>', methods=['DELETE'])
def delete_goal(goal_id):
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = database.get_db_connection()
    goal = conn.execute('SELECT * FROM goals WHERE id = ? AND user_id = ?', (goal_id, user_id)).fetchone()
    if not goal:
        conn.close()
        return jsonify({'error': 'Goal not found'}), 404
        
    conn.execute('DELETE FROM goals WHERE id = ? AND user_id = ?', (goal_id, user_id))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True, port=5000)

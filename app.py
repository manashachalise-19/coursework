"""
INSIDER THREAT DETECTION SYSTEM
================================
A comprehensive security monitoring tool for detecting potential insider threats
through user activity analysis and risk classification.

Author: Manasha Chalise
Module: Introduction to Programming
"""

# ==================== IMPORTS ====================
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import hashlib
import csv
from datetime import datetime
import matplotlib.pyplot as plt
import random

# ==================== CONSTANTS ====================
BG_MAIN = "#000000"        # Black background
SIDEBAR_BG = "#111111"     # Dark gray sidebar
HOVER = "#222222"          # Hover effect
TEXT = "#FFFFFF"           # White text
HIGH = "#FF4C4C"           # Red for high risk
MEDIUM = "#FFC857"         # Yellow for medium risk
LOW = "#4CAF50"            # Green for low risk
ACCENT = "#0078D4"         # Blue accent

# ==================== GLOBAL VARIABLES ====================
conn = None
cursor = None
current_user = None
current_role = None
root = None
login_frame = None
username_entry = None
password_entry = None
dashboard = None
content = None

# ==================== CUSTOM DATA STRUCTURES ====================
# STACK IMPLEMENTATION (LIFO)
def stack_create(capacity=50):
    """Create a new stack with specified capacity."""
    return {
        'items': [],
        'capacity': capacity,
        'top': -1
    }

def stack_push(stack, item):
    """Push item onto stack if space available."""
    if stack['top'] < stack['capacity'] - 1:
        stack['items'].append(item)
        stack['top'] += 1
        return True
    return False

def stack_pop(stack):
    """Pop and return top item from stack."""
    if stack['top'] >= 0:
        stack['top'] -= 1
        return stack['items'].pop()
    return None

def stack_peek(stack):
    """View top item without removing."""
    if stack['top'] >= 0:
        return stack['items'][stack['top']]
    return None

def stack_is_empty(stack):
    """Check if stack is empty."""
    return stack['top'] == -1

def stack_size(stack):
    """Return number of items in stack."""
    return stack['top'] + 1

# QUEUE IMPLEMENTATION (FIFO - Circular)
def queue_create(max_size=100):
    """Create a new circular queue."""
    return {
        'queue': [None] * max_size,
        'max_size': max_size,
        'front': 0,
        'rear': -1,
        'size': 0
    }

def queue_enqueue(queue, item):
    """Add item to rear of queue using circular buffer."""
    if queue['size'] < queue['max_size']:
        queue['rear'] = (queue['rear'] + 1) % queue['max_size']
        queue['queue'][queue['rear']] = item
        queue['size'] += 1
        return True
    return False

def queue_dequeue(queue):
    """Remove and return front item from queue."""
    if queue['size'] > 0:
        item = queue['queue'][queue['front']]
        queue['front'] = (queue['front'] + 1) % queue['max_size']
        queue['size'] -= 1
        return item
    return None

def queue_is_empty(queue):
    """Check if queue is empty."""
    return queue['size'] == 0

def queue_is_full(queue):
    """Check if queue is full."""
    return queue['size'] == queue['max_size']

def queue_display(queue):
    """Return all items in queue in FIFO order."""
    result = []
    for i in range(queue['size']):
        idx = (queue['front'] + i) % queue['max_size']
        if queue['queue'][idx] is not None:
            result.append(queue['queue'][idx])
    return result

# ==================== DATABASE FUNCTIONS ====================
def init_database():
    """Initialize database connection and create tables."""
    global conn, cursor
    
    try:
        conn = sqlite3.connect("insider_system.db")
        cursor = conn.cursor()
        
        # Create users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users(
            username TEXT PRIMARY KEY,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)
        
        # Create logs table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            action TEXT NOT NULL,
            risk TEXT NOT NULL,
            time TIMESTAMP NOT NULL,
            session_id TEXT
        )
        """)
        
        # Create indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_username ON logs(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_logs_time ON logs(time)")
        
        conn.commit()
        create_default_admin()
        
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def hash_password(password):
    """Hash password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()

def create_default_admin():
    """Create default admin user if not exists."""
    try:
        cursor.execute("SELECT * FROM users WHERE username='admin'")
        if not cursor.fetchone():
            hashed_pw = hash_password("admin123")
            cursor.execute(
                "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                ("admin", hashed_pw, "Admin")
            )
            conn.commit()
    except sqlite3.Error as e:
        print(f"Admin creation error: {e}")

def verify_user(username, password):
    """Verify user credentials."""
    try:
        hashed_pw = hash_password(password)
        cursor.execute(
            "SELECT role FROM users WHERE username=? AND password=?",
            (username, hashed_pw)
        )
        result = cursor.fetchone()
        return result[0] if result else None
    except sqlite3.Error as e:
        print(f"Verification error: {e}")
        return None

def reset_password(username, new_password):
    """Reset user password."""
    try:
        hashed_pw = hash_password(new_password)
        cursor.execute(
            "UPDATE users SET password=? WHERE username=?",
            (hashed_pw, username)
        )
        conn.commit()
        return cursor.rowcount > 0
    except sqlite3.Error as e:
        print(f"Password reset error: {e}")
        return False

def add_log(username, action, risk, session_id=None):
    """Add log entry to database."""
    try:
        cursor.execute("""
            INSERT INTO logs (username, action, risk, time, session_id)
            VALUES (?, ?, ?, ?, ?)
        """, (username, action, risk, datetime.now(), session_id))
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Log error: {e}")
        return False

def get_all_logs():
    """Retrieve all logs."""
    try:
        cursor.execute(
            "SELECT username, action, risk, time FROM logs ORDER BY time DESC"
        )
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Retrieval error: {e}")
        return []

def search_logs_db(keyword):
    """Search logs by username or action in database."""
    try:
        cursor.execute("""
            SELECT username, action, risk, time FROM logs 
            WHERE username LIKE ? OR action LIKE ?
            ORDER BY time DESC
        """, (f"%{keyword}%", f"%{keyword}%"))
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Search error: {e}")
        return []

def get_risk_statistics():
    """Get risk statistics."""
    stats = {'high': 0, 'medium': 0, 'low': 0, 'total': 0}
    try:
        cursor.execute("SELECT risk FROM logs")
        for row in cursor.fetchall():
            stats['total'] += 1
            if row[0] == 'High':
                stats['high'] += 1
            elif row[0] == 'Medium':
                stats['medium'] += 1
            else:
                stats['low'] += 1
    except sqlite3.Error as e:
        print(f"Statistics error: {e}")
    return stats

def clear_all_logs():
    """Clear all logs."""
    try:
        cursor.execute("DELETE FROM logs")
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Clear logs error: {e}")
        return False

def get_all_users():
    """Get list of all usernames."""
    try:
        cursor.execute("SELECT username FROM users")
        return [row[0] for row in cursor.fetchall()]
    except sqlite3.Error as e:
        print(f"User retrieval error: {e}")
        return []

# ==================== RISK CLASSIFICATION ====================
HIGH_RISK_KEYWORDS = ['delete', 'remove', 'destroy', 'erase', 'terminate', 'drop']
MEDIUM_RISK_KEYWORDS = ['download', 'upload', 'copy', 'transfer', 'export', 'modify']

def classify_risk(action):
    """Classify action risk level based on keywords."""
    if not action:
        return 'Low'
    
    action_lower = action.lower()
    
    for keyword in HIGH_RISK_KEYWORDS:
        if keyword in action_lower:
            return 'High'
    
    for keyword in MEDIUM_RISK_KEYWORDS:
        if keyword in action_lower:
            return 'Medium'
    
    return 'Low'

def get_risk_color(risk):
    """Get color code for risk level."""
    colors = {'High': HIGH, 'Medium': MEDIUM, 'Low': LOW}
    return colors.get(risk, TEXT)

def get_risk_icon(risk):
    """Get icon for risk level."""
    icons = {'High': '🔴', 'Medium': '🟡', 'Low': '🟢'}
    return icons.get(risk, '⚪')

# ==================== CSV PROCESSING ====================
def validate_csv(filepath):
    """Validate CSV file structure."""
    try:
        with open(filepath, 'r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            header = next(reader, None)
            
            if not header:
                return False, "Empty CSV file"
            if len(header) < 2:
                return False, "CSV must have at least 2 columns"
            
            first_row = next(reader, None)
            if first_row and len(first_row) < 2:
                return False, "Data rows must have at least 2 columns"
            
            return True, "CSV structure is valid"
    except Exception as e:
        return False, f"Validation error: {e}"

def import_csv(filepath):
    """Import logs from CSV file."""
    try:
        count = 0
        with open(filepath, 'r', newline='', encoding='utf-8') as file:
            reader = csv.reader(file)
            next(reader)  # Skip header
            
            for row in reader:
                if len(row) >= 2:
                    username = row[0].strip()
                    action = row[1].strip()
                    
                    if username and action:
                        risk = classify_risk(action)
                        if add_log(username, action, risk):
                            count += 1
        
        return True, f"Imported {count} logs", count
    except Exception as e:
        return False, f"Error: {e}", 0

def export_csv(filepath, logs):
    """Export logs to CSV file."""
    try:
        with open(filepath, 'w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(['Username', 'Action', 'Risk', 'Time'])
            for log in logs:
                writer.writerow(log)
        return True, f"Exported {len(logs)} logs"
    except Exception as e:
        return False, f"Error: {e}"

# ==================== ACTIVITY SIMULATION ====================
SIM_ACTIONS = [
    "Deleted confidential client database",
    "Removed security audit logs",
    "Destroyed backup files",
    "Terminated security protocols",
    "Downloaded employee records",
    "Uploaded files to external server",
    "Copied sensitive documents",
    "Transferred data to USB drive",
    "Logged into system",
    "Viewed dashboard",
    "Opened help documentation",
    "Searched user directory"
]

def generate_random_activity():
    """Generate random activity."""
    action = random.choice(SIM_ACTIONS)
    risk = classify_risk(action)
    return action, risk

def simulate_activity():
    """Simulate random user activity."""
    users = get_all_users()
    if not users:
        users = ['admin']
    
    action, risk = generate_random_activity()
    username = random.choice(users)
    
    if add_log(username, action, risk):
        messagebox.showinfo("Success", 
                           f"Simulated activity added:\nUser: {username}\nAction: {action}\nRisk: {risk}")
    else:
        messagebox.showerror("Error", "Failed to simulate activity")

# ==================== GUI FUNCTIONS ====================
def clear_frame(frame):
    """Clear all widgets from a frame."""
    for widget in frame.winfo_children():
        widget.destroy()

def create_login_screen():
    """Create login interface."""
    global login_frame, username_entry, password_entry
    
    for widget in root.winfo_children():
        widget.destroy()
    
    login_frame = tk.Frame(root, bg=BG_MAIN)
    login_frame.pack(fill="both", expand=True)
    
    # Title
    title_frame = tk.Frame(login_frame, bg=BG_MAIN)
    title_frame.pack(pady=100)
    
    tk.Label(title_frame, text="INSIDER THREAT", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 32, "bold")).pack()
    tk.Label(title_frame, text="DETECTION SYSTEM", fg=TEXT, bg=BG_MAIN,
            font=("Segoe UI", 28, "bold")).pack()
    
    # Login form
    form_frame = tk.Frame(login_frame, bg=SIDEBAR_BG, padx=50, pady=30)
    form_frame.pack()
    
    tk.Label(form_frame, text="LOGIN", fg=ACCENT, bg=SIDEBAR_BG,
            font=("Segoe UI", 18, "bold")).pack(pady=10)
    
    tk.Label(form_frame, text="Username", fg=TEXT, bg=SIDEBAR_BG).pack()
    username_entry = tk.Entry(form_frame, bg=HOVER, fg=TEXT, width=25)
    username_entry.pack(pady=5)
    
    tk.Label(form_frame, text="Password", fg=TEXT, bg=SIDEBAR_BG).pack()
    password_entry = tk.Entry(form_frame, show="*", bg=HOVER, fg=TEXT, width=25)
    password_entry.pack(pady=5)
    
    # Buttons
    button_frame = tk.Frame(form_frame, bg=SIDEBAR_BG)
    button_frame.pack(pady=20)
    
    tk.Button(button_frame, text="Login", bg=ACCENT, fg=TEXT,
             width=15, command=login).pack(side="left", padx=5)
    tk.Button(button_frame, text="Forgot Password", bg=HOVER, fg=TEXT,
             width=15, command=forgot_password).pack(side="left", padx=5)
    
    password_entry.bind('<Return>', lambda e: login())

def login():
    """Handle login attempt."""
    global current_user, current_role
    
    username = username_entry.get().strip()
    password = password_entry.get().strip()
    
    if not username or not password:
        messagebox.showerror("Error", "Please enter both fields")
        return
    
    role = verify_user(username, password)
    
    if role:
        current_user = username
        current_role = role
        add_log(username, "Logged into system", "Low")
        create_dashboard()
    else:
        messagebox.showerror("Error", "Invalid credentials")

def forgot_password():
    """Handle password reset."""
    def reset():
        username = user_entry.get().strip()
        new_pw = pw_entry.get().strip()
        confirm_pw = confirm_entry.get().strip()
        
        if not username or not new_pw or not confirm_pw:
            messagebox.showerror("Error", "Please fill all fields")
            return
        
        if new_pw != confirm_pw:
            messagebox.showerror("Error", "Passwords do not match")
            return
        
        if len(new_pw) < 6:
            messagebox.showerror("Error", "Password must be at least 6 characters")
            return
        
        if reset_password(username, new_pw):
            messagebox.showinfo("Success", f"Password reset for '{username}'")
            fp_window.destroy()
        else:
            messagebox.showerror("Error", "Username not found")
    
    fp_window = tk.Toplevel(root)
    fp_window.title("Reset Password")
    fp_window.geometry("400x300")
    fp_window.configure(bg=BG_MAIN)
    fp_window.grab_set()
    
    tk.Label(fp_window, text="RESET PASSWORD", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 16, "bold")).pack(pady=20)
    
    tk.Label(fp_window, text="Username", fg=TEXT, bg=BG_MAIN).pack()
    user_entry = tk.Entry(fp_window, bg=HOVER, fg=TEXT, width=25)
    user_entry.pack(pady=5)
    
    tk.Label(fp_window, text="New Password", fg=TEXT, bg=BG_MAIN).pack()
    pw_entry = tk.Entry(fp_window, show="*", bg=HOVER, fg=TEXT, width=25)
    pw_entry.pack(pady=5)
    
    tk.Label(fp_window, text="Confirm Password", fg=TEXT, bg=BG_MAIN).pack()
    confirm_entry = tk.Entry(fp_window, show="*", bg=HOVER, fg=TEXT, width=25)
    confirm_entry.pack(pady=5)
    
    tk.Button(fp_window, text="Reset Password", bg=ACCENT, fg=TEXT,
             font=("Segoe UI", 11, "bold"), width=20, command=reset).pack(pady=20)

def create_dashboard():
    """Create main dashboard interface."""
    global dashboard, content
    
    for widget in root.winfo_children():
        widget.destroy()
    
    dashboard = tk.Frame(root, bg=BG_MAIN)
    dashboard.pack(fill="both", expand=True)
    
    create_sidebar()
    
    content = tk.Frame(dashboard, bg=BG_MAIN)
    content.pack(side="left", fill="both", expand=True, padx=5, pady=5)
    
    show_dashboard_home()

def create_sidebar():
    """Create navigation sidebar."""
    sidebar = tk.Frame(dashboard, bg=SIDEBAR_BG, width=250)
    sidebar.pack(side="left", fill="y")
    sidebar.pack_propagate(False)
    
    # User info
    user_frame = tk.Frame(sidebar, bg=SIDEBAR_BG, height=100)
    user_frame.pack(fill="x", pady=20)
    user_frame.pack_propagate(False)
    
    tk.Label(user_frame, text="👤", fg=TEXT, bg=SIDEBAR_BG,
            font=("Segoe UI", 30)).pack()
    tk.Label(user_frame, text=current_user, fg=ACCENT, bg=SIDEBAR_BG,
            font=("Segoe UI", 12, "bold")).pack()
    tk.Label(user_frame, text=f"Role: {current_role}", fg="#888888",
            bg=SIDEBAR_BG, font=("Segoe UI", 10)).pack()
    
    ttk.Separator(sidebar, orient='horizontal').pack(fill='x', padx=20, pady=10)
    
    # Navigation buttons
    nav_items = [
        ("🏠 Dashboard Home", show_dashboard_home),
        ("ℹ Overview", show_overview),
        ("📥 Upload CSV", upload_csv),
        ("📄 View Logs", show_logs),
        ("🔍 Search Logs", search_logs_gui),
        ("📊 Bar Graph", show_bar_graph),
        ("🥧 Pie Chart", show_pie_chart),
        ("📝 Simulate Activity", simulate_activity),
        ("📁 Export Logs", export_logs),
        ("🗑 Clear Logs", clear_logs),
        ("🚪 Logout", logout)
    ]
    
    for text, command in nav_items:
        btn = tk.Button(sidebar, text=text, bg=SIDEBAR_BG, fg=TEXT,
                       activebackground=HOVER, activeforeground=TEXT,
                       bd=0, font=("Segoe UI", 11), anchor="w",
                       padx=20, command=command)
        btn.pack(fill="x", pady=2)
        
        btn.bind("<Enter>", lambda e, b=btn: b.config(bg=HOVER))
        btn.bind("<Leave>", lambda e, b=btn: b.config(bg=SIDEBAR_BG))

def show_dashboard_home():
    """Show dashboard home with statistics."""
    clear_frame(content)
    
    header_frame = tk.Frame(content, bg=BG_MAIN)
    header_frame.pack(fill="x", pady=20)
    
    tk.Label(header_frame, text="DASHBOARD", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 24, "bold")).pack()
    tk.Label(header_frame, text=f"Welcome back, {current_user}!",
            fg="#888888", bg=BG_MAIN, font=("Segoe UI", 12)).pack()
    
    stats = get_risk_statistics()
    
    cards_frame = tk.Frame(content, bg=BG_MAIN)
    cards_frame.pack(pady=30)
    
    # Total logs card
    total_card = tk.Frame(cards_frame, bg=SIDEBAR_BG, width=200, height=120)
    total_card.pack(side="left", padx=10)
    total_card.pack_propagate(False)
    tk.Label(total_card, text="TOTAL LOGS", fg="#888888", bg=SIDEBAR_BG,
            font=("Segoe UI", 10)).pack(pady=(20,5))
    tk.Label(total_card, text=str(stats['total']), fg=TEXT, bg=SIDEBAR_BG,
            font=("Segoe UI", 24, "bold")).pack()
    
    # High risk card
    high_card = tk.Frame(cards_frame, bg=SIDEBAR_BG, width=200, height=120)
    high_card.pack(side="left", padx=10)
    high_card.pack_propagate(False)
    tk.Label(high_card, text="HIGH RISK", fg="#888888", bg=SIDEBAR_BG,
            font=("Segoe UI", 10)).pack(pady=(20,5))
    tk.Label(high_card, text=str(stats['high']), fg=HIGH, bg=SIDEBAR_BG,
            font=("Segoe UI", 24, "bold")).pack()
    
    # Medium risk card
    medium_card = tk.Frame(cards_frame, bg=SIDEBAR_BG, width=200, height=120)
    medium_card.pack(side="left", padx=10)
    medium_card.pack_propagate(False)
    tk.Label(medium_card, text="MEDIUM RISK", fg="#888888", bg=SIDEBAR_BG,
            font=("Segoe UI", 10)).pack(pady=(20,5))
    tk.Label(medium_card, text=str(stats['medium']), fg=MEDIUM, bg=SIDEBAR_BG,
            font=("Segoe UI", 24, "bold")).pack()
    
    # Low risk card
    low_card = tk.Frame(cards_frame, bg=SIDEBAR_BG, width=200, height=120)
    low_card.pack(side="left", padx=10)
    low_card.pack_propagate(False)
    tk.Label(low_card, text="LOW RISK", fg="#888888", bg=SIDEBAR_BG,
            font=("Segoe UI", 10)).pack(pady=(20,5))
    tk.Label(low_card, text=str(stats['low']), fg=LOW, bg=SIDEBAR_BG,
            font=("Segoe UI", 24, "bold")).pack()

def show_overview():
    """Show system overview."""
    clear_frame(content)
    
    tk.Label(content, text="SYSTEM OVERVIEW", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 20, "bold")).pack(pady=20)
    
    overview_text = """
    INSIDER THREAT DETECTION SYSTEM
    ================================
    
    This system monitors user activities to detect potential insider threats
    within an organization's network. It classifies activities into risk levels
    and provides visualization tools for security analysis.
    
    RISK CLASSIFICATION:
    • 🔴 HIGH RISK: Critical actions like data deletion
    • 🟡 MEDIUM RISK: Suspicious downloads
    • 🟢 LOW RISK: Normal system usage
    
    KEY FEATURES:
    • Secure authentication with password hashing
    • Activity logging and monitoring
    • CSV import/export
    • Data visualization with graphs
    • Search and filter capabilities
    """
    
    text_widget = tk.Text(content, bg=SIDEBAR_BG, fg=TEXT,
                         font=("Segoe UI", 11), wrap="word", padx=20, pady=20)
    text_widget.insert("1.0", overview_text)
    text_widget.config(state="disabled")
    text_widget.pack(fill="both", expand=True, padx=50, pady=20)

def show_logs():
    """Display all logs in a table."""
    clear_frame(content)
    
    tk.Label(content, text="ACTIVITY LOGS", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 18, "bold")).pack(pady=10)
    
    tree_frame = tk.Frame(content, bg=SIDEBAR_BG)
    tree_frame.pack(fill="both", expand=True, padx=20, pady=10)
    
    tree = ttk.Treeview(tree_frame, columns=("User", "Action", "Risk", "Time"),
                       show="headings")
    
    tree.heading("User", text="Username")
    tree.heading("Action", text="Action")
    tree.heading("Risk", text="Risk Level")
    tree.heading("Time", text="Timestamp")
    
    tree.column("User", width=150)
    tree.column("Action", width=400)
    tree.column("Risk", width=100)
    tree.column("Time", width=150)
    
    v_scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=tree.yview)
    h_scrollbar = ttk.Scrollbar(tree_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=v_scrollbar.set, xscrollcommand=h_scrollbar.set)
    
    tree.grid(row=0, column=0, sticky="nsew")
    v_scrollbar.grid(row=0, column=1, sticky="ns")
    h_scrollbar.grid(row=1, column=0, sticky="ew")
    
    tree_frame.grid_rowconfigure(0, weight=1)
    tree_frame.grid_columnconfigure(0, weight=1)
    
    logs = get_all_logs()
    for log in logs:
        tree.insert("", tk.END, values=log)
    
    tk.Label(content, text=f"Total Logs: {len(logs)}", fg="#888888",
            bg=BG_MAIN, font=("Segoe UI", 10)).pack(pady=5)

def search_logs_gui():
    """Search logs by keyword in GUI."""
    clear_frame(content)
    
    tk.Label(content, text="SEARCH LOGS", fg=ACCENT, bg=BG_MAIN,
            font=("Segoe UI", 18, "bold")).pack(pady=10)
    
    # Search frame
    search_frame = tk.Frame(content, bg=BG_MAIN)
    search_frame.pack(pady=20)
    
    tk.Label(search_frame, text="Enter Username or Action:", fg=TEXT,
            bg=BG_MAIN, font=("Segoe UI", 11)).pack(side="left", padx=5)
    
    search_entry = tk.Entry(search_frame, bg=HOVER, fg=TEXT,
                           font=("Segoe UI", 11), width=30)
    search_entry.pack(side="left", padx=5)
    
    # Results frame
    results_frame = tk.Frame(content, bg=SIDEBAR_BG)
    results_frame.pack(fill="both", expand=True, padx=20, pady=10)
    
    # Treeview for results
    tree = ttk.Treeview(results_frame, columns=("User", "Action", "Risk", "Time"),
                       show="headings")
    
    tree.heading("User", text="Username")
    tree.heading("Action", text="Action")
    tree.heading("Risk", text="Risk Level")
    tree.heading("Time", text="Timestamp")
    
    tree.column("User", width=150)
    tree.column("Action", width=400)
    tree.column("Risk", width=100)
    tree.column("Time", width=150)
    
    scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=tree.yview)
    tree.configure(yscrollcommand=scrollbar.set)
    
    tree.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")
    
    def perform_search():
        keyword = search_entry.get().strip()
        if not keyword:
            messagebox.showwarning("Warning", "Please enter a search term")
            return
        
        # Clear previous results
        for item in tree.get_children():
            tree.delete(item)
        
        # Call database search function
        results = search_logs_db(keyword)
        for result in results:
            tree.insert("", tk.END, values=result)
        
        status_label.config(text=f"Found {len(results)} result(s)")
    
    # Search button
    tk.Button(search_frame, text="🔍 Search", bg=ACCENT, fg=TEXT,
             font=("Segoe UI", 11, "bold"), command=perform_search).pack(side="left", padx=5)
    
    # Status label
    status_label = tk.Label(content, text="", fg="#888888",
                           bg=BG_MAIN, font=("Segoe UI", 10))
    status_label.pack(pady=5)

def upload_csv():
    """Upload and process CSV file."""
    filepath = filedialog.askopenfilename(
        title="Select CSV File",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    
    if not filepath:
        return
    
    valid, msg = validate_csv(filepath)
    if not valid:
        messagebox.showerror("Validation Error", msg)
        return
    
    success, msg, count = import_csv(filepath)
    
    if success:
        messagebox.showinfo("Success", msg)
        add_log(current_user, f"Uploaded CSV file with {count} logs", "Low")
    else:
        messagebox.showerror("Error", msg)

def export_logs():
    """Export logs to CSV file."""
    filepath = filedialog.asksaveasfilename(
        title="Save CSV File",
        defaultextension=".csv",
        filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")]
    )
    
    if not filepath:
        return
    
    logs = get_all_logs()
    
    if not logs:
        messagebox.showwarning("Warning", "No logs to export")
        return
    
    success, msg = export_csv(filepath, logs)
    
    if success:
        messagebox.showinfo("Success", msg)
        add_log(current_user, f"Exported {len(logs)} logs to CSV", "Low")
    else:
        messagebox.showerror("Error", msg)

def clear_logs():
    """Clear all logs after confirmation."""
    if messagebox.askyesno("Confirm", "Are you sure you want to clear all logs?"):
        if clear_all_logs():
            messagebox.showinfo("Success", "All logs cleared successfully")
            add_log(current_user, "Cleared all logs", "Medium")
        else:
            messagebox.showerror("Error", "Failed to clear logs")

def show_bar_graph():
    """Display bar graph of risk distribution."""
    stats = get_risk_statistics()
    
    if stats['total'] == 0:
        messagebox.showwarning("Warning", "No data to display")
        return
    
    plt.figure(figsize=(10, 6))
    
    risks = ['High', 'Medium', 'Low']
    counts = [stats['high'], stats['medium'], stats['low']]
    colors = [HIGH, MEDIUM, LOW]
    
    bars = plt.bar(risks, counts, color=colors, edgecolor='white', linewidth=2)
    
    plt.title('Risk Distribution Analysis', fontsize=16, fontweight='bold', pad=20)
    plt.xlabel('Risk Level', fontsize=12)
    plt.ylabel('Number of Incidents', fontsize=12)
    
    for bar, count in zip(bars, counts):
        height = bar.get_height()
        plt.text(bar.get_x() + bar.get_width()/2., height,
                f'{count}', ha='center', va='bottom', fontsize=11, fontweight='bold')
    
    plt.grid(axis='y', alpha=0.3)
    plt.tight_layout()
    plt.show()

def show_pie_chart():
    """Display pie chart of risk percentages."""
    stats = get_risk_statistics()
    
    if stats['total'] == 0:
        messagebox.showwarning("Warning", "No data to display")
        return
    
    plt.figure(figsize=(8, 8))
    
    labels = ['High Risk', 'Medium Risk', 'Low Risk']
    sizes = [stats['high'], stats['medium'], stats['low']]
    colors = [HIGH, MEDIUM, LOW]
    
    non_zero = [(l, s, c) for l, s, c in zip(labels, sizes, colors) if s > 0]
    if non_zero:
        labels, sizes, colors = zip(*non_zero)
    
    wedges, texts, autotexts = plt.pie(sizes, labels=labels, colors=colors,
                                       autopct='%1.1f%%', startangle=90,
                                       textprops={'fontsize': 12, 'fontweight': 'bold'})
    
    plt.title('Risk Distribution Percentage', fontsize=16, fontweight='bold', pad=20)
    plt.axis('equal')
    plt.tight_layout()
    plt.show()

def logout():
    """Handle logout."""
    if messagebox.askyesno("Logout", "Are you sure you want to logout?"):
        global current_user, current_role
        
        add_log(current_user, "Logged out of system", "Low")
        
        current_user = None
        current_role = None
        
        create_login_screen()

def on_closing():
    """Handle application closing."""
    if messagebox.askokcancel("Quit", "Do you want to quit the application?"):
        if conn:
            conn.close()
        root.destroy()

# ==================== MAIN FUNCTION ====================
def main():
    """Main entry point for the application."""
    global root
    
    try:
        init_database()
        
        root = tk.Tk()
        root.title("Insider Threat Detection System")
        root.geometry("1200x750")
        root.configure(bg=BG_MAIN)
        
        root.protocol("WM_DELETE_WINDOW", on_closing)
        
        create_login_screen()
        
        root.mainloop()
        
    except Exception as e:
        print(f"Fatal error: {e}")
        messagebox.showerror("Fatal Error", f"Application failed to start: {e}")

if __name__ == "__main__":
    main()
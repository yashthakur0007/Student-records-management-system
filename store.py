"""
=====================================================================
 store.py  -  BACKEND: data model + SQLite storage + business rules
=====================================================================
 SQLite is only the PERMANENT storage. Searching and sorting are done by
 the DSA code in dsa.py on the in-memory linked list / arrays / hash maps.
=====================================================================
"""

import os
import random
import re
import sqlite3
import threading
from contextlib import closing
from dataclasses import dataclass
from functools import wraps

from werkzeug.security import generate_password_hash

from dsa import StudentLinkedList, HashMap, merge_sort, quick_sort, binary_search

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(BASE_DIR, "srms.db")


# =====================================================================
#  DATA MODEL
# =====================================================================
@dataclass
class Student:
    roll: str
    name: str
    course: str
    marks: int                      # 0-100
    cgpa: float                     # 0-10
    attendance: float               # percentage
    marks_verified: bool = False    # set by staff
    attendance_verified: bool = False


# =====================================================================
#  STORE : SQLite (permanent storage) + in-memory DSA structures
# =====================================================================
LOCK = threading.RLock()          # the dev server is multi-threaded -> protect shared data


def locked(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        with LOCK:
            return func(*args, **kwargs)
    return wrapper


def sql(query, args=()):
    """Run one parameterised SQL statement (parameters stop SQL injection)."""
    with closing(sqlite3.connect(DB_FILE)) as con:
        cur = con.execute(query, args)
        rows = cur.fetchall()
        con.commit()
        return rows


class Store:
    def __init__(self):
        sql("""CREATE TABLE IF NOT EXISTS students(
                 roll TEXT PRIMARY KEY, name TEXT, course TEXT, marks INTEGER, cgpa REAL,
                 attendance REAL, marks_verified INTEGER DEFAULT 0, att_verified INTEGER DEFAULT 0)""")
        sql("""CREATE TABLE IF NOT EXISTS users(
                 username TEXT PRIMARY KEY, pw_hash TEXT, role TEXT, roll TEXT)""")
        if not sql("SELECT 1 FROM users WHERE username='admin'"):
            sql("INSERT INTO users VALUES('admin', ?, 'staff', '')", (generate_password_hash("admin123"),))
            print("First run: staff account created -> admin / admin123")
        self.list = StudentLinkedList()
        for r in sql("SELECT roll,name,course,marks,cgpa,attendance,marks_verified,att_verified FROM students"):
            self.list.append(Student(r[0], r[1], r[2], r[3], r[4], r[5], bool(r[6]), bool(r[7])))
        self.rebuild()

    def rebuild(self):
        """Rebuild the array / hash-map views after every change."""
        self.array = self.list.to_array()
        self.roll_map = HashMap()                           # roll  -> Student
        self.marks_map = HashMap()                          # marks -> [Students]
        for s in self.array:
            self.roll_map.put(s.roll, s)
            g = self.marks_map.get(s.marks)
            if g is None:
                self.marks_map.put(s.marks, [s])
            else:
                g.append(s)
        self.sorted_by_roll = list(self.array)
        quick_sort(self.sorted_by_roll, key=lambda s: s.roll)

    @staticmethod
    def validate(roll, name, course, marks, cgpa, attendance):
        roll = (roll or "").strip().upper()
        if not re.fullmatch(r"[A-Z0-9]{3,15}", roll):
            raise ValueError("Roll number: 3-15 letters/digits only.")
        name, course = (name or "").strip(), (course or "").strip()
        if not name or len(name) > 50:
            raise ValueError("Name is required (max 50 characters).")
        if not course or len(course) > 50:
            raise ValueError("Course is required (max 50 characters).")
        try:
            marks, cgpa, attendance = int(marks), float(cgpa), float(attendance)
        except (TypeError, ValueError):
            raise ValueError("Marks must be a whole number; CGPA and attendance must be numbers.")
        if not 0 <= marks <= 100:
            raise ValueError("Marks must be between 0 and 100.")
        if not 0 <= cgpa <= 10:
            raise ValueError("CGPA must be between 0 and 10.")
        if not 0 <= attendance <= 100:
            raise ValueError("Attendance must be between 0 and 100.")
        return roll, name, course, marks, round(cgpa, 2), round(attendance, 1)

    # ---------- staff operations ----------
    @locked
    def add(self, roll, name, course, marks, cgpa, attendance, password=""):
        roll, name, course, marks, cgpa, attendance = self.validate(roll, name, course, marks, cgpa, attendance)
        if self.roll_map.contains(roll):                    # O(1) duplicate check (hash map)
            raise ValueError(f"Roll number {roll} already exists.")
        if password and len(password) < 6:
            raise ValueError("Password must be at least 6 characters (or leave blank).")
        self.list.append(Student(roll, name, course, marks, cgpa, attendance))
        sql("INSERT INTO students VALUES(?,?,?,?,?,?,0,0)", (roll, name, course, marks, cgpa, attendance))
        sql("INSERT INTO users VALUES(?,?,?,?)", (roll, generate_password_hash(password or roll), "student", roll))
        self.rebuild()

    @locked
    def update(self, roll, name, course, marks, cgpa, attendance):
        roll, name, course, marks, cgpa, attendance = self.validate(roll, name, course, marks, cgpa, attendance)
        s = self.roll_map.get(roll)
        if s is None:
            raise ValueError("Student not found.")
        if s.marks != marks:
            s.marks_verified = False                        # changed data must be re-verified
        if s.attendance != attendance:
            s.attendance_verified = False
        s.name, s.course, s.marks, s.cgpa, s.attendance = name, course, marks, cgpa, attendance
        sql("UPDATE students SET name=?,course=?,marks=?,cgpa=?,attendance=?,marks_verified=?,att_verified=? WHERE roll=?",
            (name, course, marks, cgpa, attendance, int(s.marks_verified), int(s.attendance_verified), roll))
        self.rebuild()

    @locked
    def delete(self, roll):
        roll = (roll or "").strip().upper()
        if not self.list.remove(roll):
            raise ValueError("Student not found.")
        sql("DELETE FROM students WHERE roll=?", (roll,))
        sql("DELETE FROM users WHERE username=? AND role='student'", (roll,))
        self.rebuild()

    @locked
    def verify(self, roll, what):
        s = self.roll_map.get((roll or "").strip().upper())
        if s is None:
            raise ValueError("Student not found.")
        if what == "marks":
            s.marks_verified = True
            sql("UPDATE students SET marks_verified=1 WHERE roll=?", (s.roll,))
        elif what == "attendance":
            s.attendance_verified = True
            sql("UPDATE students SET att_verified=1 WHERE roll=?", (s.roll,))
        else:
            raise ValueError("Unknown verification type.")

    @locked
    def reset_password(self, roll, new_password):
        roll = (roll or "").strip().upper()
        if not self.roll_map.contains(roll) or len(new_password or "") < 6:
            raise ValueError("Student must exist and password needs 6+ characters.")
        sql("UPDATE users SET pw_hash=? WHERE username=? AND role='student'", (generate_password_hash(new_password), roll))

    @locked
    def search(self, roll):
        """Binary search on the roll-sorted array."""
        idx = binary_search(self.sorted_by_roll, (roll or "").strip().upper(), key=lambda s: s.roll)
        return self.sorted_by_roll[idx] if idx != -1 else None

    @locked
    def sorted_by(self, field, descending=True):
        return merge_sort(self.array, key=lambda s: getattr(s, field), descending=descending)

    @locked
    def top_n(self, n=10):
        return merge_sort(self.array, key=lambda s: (s.cgpa, s.marks), descending=True)[:n]

    @locked
    def same_marks(self):
        groups = [(m, g) for m, g in self.marks_map.items() if len(g) > 1]
        groups = merge_sort(groups, key=lambda t: t[0], descending=True)
        return [s for _, g in groups for s in g]

    @locked
    def get_all(self):
        return list(self.array)

    @locked
    def get(self, roll):
        return self.roll_map.get(roll)

    @locked
    def load_sample(self, count=50):
        first = ["Aarav", "Riya", "Kabir", "Simran", "Arjun", "Meera", "Rohan", "Anaya", "Vivaan", "Isha"]
        last = ["Sharma", "Singh", "Verma", "Gill", "Kaur", "Mehta", "Bansal", "Kapoor", "Jain", "Arora"]
        added, n = 0, 1
        while added < count and n < 10000:
            roll = f"CS24{n:03d}"
            n += 1
            if self.roll_map.contains(roll):
                continue
            self.add(roll, f"{random.choice(first)} {random.choice(last)}", "B.Tech CSE",
                     random.randint(40, 100), round(random.uniform(5, 10), 2), round(random.uniform(60, 100), 1))
            added += 1
        return added

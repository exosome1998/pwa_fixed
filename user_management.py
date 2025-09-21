import sqlite3 as sql
import time
import random
import html
import bcrypt


def insertUser(username, password, DoB):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    # Hash the password before storing
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    cur.execute(
        "INSERT INTO users (username,password,dateOfBirth) VALUES (?,?,?)",
        (username, hashed_password, DoB),
    )
    con.commit()
    con.close()


def retrieveUsers(username, password):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cur.fetchone()
    if user == None:
        con.close()
        return False
    else:
        # Verify hashed password
        stored_hash = user[2]  # Assuming password is in column 2
        if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
            # Plain text log of visitor count as requested by Unsecure PWA management
            with open("visitor_log.txt", "r") as file:
                number = int(file.read().strip())
                number += 1
            with open("visitor_log.txt", "w") as file:
                file.write(str(number))
            # Simulate response time of heavy app for testing purposes
            time.sleep(random.randint(80, 90) / 1000)
            con.close()
            return True
        else:
            con.close()
            return False


def insertFeedback(feedback):
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    cur.execute("INSERT INTO feedback (feedback) VALUES (?)", (feedback,))
    con.commit()
    con.close()


def listFeedback():
    con = sql.connect("database_files/database.db")
    cur = con.cursor()
    data = cur.execute("SELECT * FROM feedback").fetchall()
    con.close()
    f = open("templates/partials/success_feedback.html", "w")
    for row in data:
        f.write("<p>\n")
        f.write(f"{html.escape(row[1])}\n")
        f.write("</p>\n")
    f.close()

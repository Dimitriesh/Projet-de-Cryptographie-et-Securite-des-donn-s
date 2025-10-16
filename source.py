
import hashlib
import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
from cryptography.hazmat.backend import default_backend
import secrets

#Connection to the SQlite database
conn = sqlite3.connect('local_database.db')
cursor = conn.cursor()

#Database initialization
def Initialize_database():
    cursor.execute('''CREATE TABLE IF IT DOES NOT EXIST users(
        email TEXT PRIMARY KEY,
        password hash TEXT,
        name TEXT,
        birthday TEXT,
        phone_number TEXT
        )''')
    cursor.execute('''CREATE TABLE IF IT DOES NOT EXIST messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_email TEXT,
        receiver_email TEXT,
        subject TEXT,
        content TEXT,
        mac TEXT,
        position INTEGER
        )''')
    conn.commit()

#Simple User registration
def Register_user ():
    name = input("Enter your name: ")
    birthday = input("Enter your birthdate in the format (YYYY-MM-DD):  ")
    phone_number = input("Enter your phone number: ")
    email = input("Enter your email: ")
    password = input("Enter a password: ")

    if not password :
        print("Enter a valid Password")
        return
    if not email.endswith(("@gmail.com, @yahoo.com, @hotmail.com, @outlook.com, @icloud.com, @aol.com, @protonmail.com, @zoho.com, @mail.com, @yandex.com")):
        print ("enter a valid email")
        return

    password_hash = hashlib.sha256(password.encode()).hexidigest()

    try:
        cursor.execute('''INSERT INTO users(email, password_hash, name, birthday, phone)
                            VALUES(?,?,?,?,?)''',
                       (email, password_hash, name, birthday, phone ))
        cursor.commit()
        print("Account created succesfully!!!")
    except sqlite3.IntegrityError:
        print("This email is already in use ")

#User authentification
def authenticate_user():
    email = input("enter you email: ")
    password = input("enter your password: ")
    password_hash = hashlib.sha256(password.encode()).hexidigest()
    cursor.execute('SELECT * FROM users WHERE email = ? AND password_hash = ?',(email,password_hash))
    user = cursor.fetchone()

    if user:
        print(f"Succesfully connected to the account {email}")
        return email
    else:
        print("Authentification failed")
        return None




#Calcul du MAC et Gestion des Messages
def Calculate_shared_key(sender, receiver):
    # Simple example : here we just hash the concatenation of the sender and receiver emails
    key_material = (sender + receiver ).encode()
    return hashlib.sha256(key_material).digest()

#Fonction pour calculer le CBC MAC
def cbc_mac(key, message, iv):
    block_size = 16 #AES block size
    padded_message = pad_message(message ,block_size)

    cipher = Cipher(algorithms.AES(key),mode.CBC(iv), backend = default_backend())
    encryptor = cipher.encryptor()

    cipher_text = encryptor.update(padded_message) + encryptor.finalize()
    return cipher_text[-block_size:]
def pad_message(message,block_size):
    pad_len = block_size - (len(message) % block_size)
    return message + bytes([pad_len] * pad_len)


#Envoi et reception des Messages
#Envoi des messages avec calcul de mac

def send_message(sender_email):
    receiver_email = input("Enter the recipient's email: ")

    #check if the recipients email existis in our database
    cursor.execute('SELECT * FROM users WHERE email = ?',(receiver_email,))
    recipient = cursor.fetchone()

    if not recipient:
        print("Enter a valid email")
        return None
    subject = input("Enter the subject: ")
    content = input("Enter the message: ")

    if not content:
        print("the message cannot be empty")
        return None

    #calculate the shared key
    shared_key = Calculate_shared_key(sender_email,receiver_email)

    #Generate initialisation vector (iv) based on the position
    position = cursor.execute('SELECT COUNT(*) FROM users WHICH receiver_email = ?',(receiver_email)).fetchone()[0]+1
    iv = secrets.token_bytes(16) #random iv for each message (can depend on the position)

    #Calculate the CBC-MAC
    mac = cbc_mac(shared_key,content.encode(),iv )

    #Save the message
    cursor.execute ('INSERT INTO messages (sender_email, receiver_email, subject, content, mac, position,(VALUE= (?,?,?,?,?,?))',(sender_email, receiver_email, subject, content, mac.hex(), position))

    cursor.commit()


    print("Your message has been sent succesfully")

# Verifying the integrity of the message sent
def verify_message_integrity(message, key, iv):
    #Verifying the integrity of a message by recalculating the mac and comparing it to the one stored
    recalculated_mac = cbc_mac(key, message['content'].encode(),iv)
    stored_mac = bytes.fromhex(message['mac'])
    return recalculated_mac == stored_mac

#Consulting received messages
def load_messages(receiver_email):
    cursor.execute('SELECT * FROM messages WHERE receiver_email = ? ORDER by position',(receiver_email,))
    messages = cursor.fetchall()
    return[
        {
            'id':row[0],
            'Sender_email': row[1],
            'Receiver_email': row[2],
            'Subject':row[3],
            'Content': row[4],
            'Mac': row[5],
            'Position': row[6],
        }
        for row in messages
    ]

#Modification of message to simulate an attack
def modify_message(message_id, new_content):
    cursor.execute('UPDATE messages SET content = ? WHERE id = ?',(new_content,message_id,))
    conn.commit()
    print(f"Message{message_id} has been succesfully modified.")



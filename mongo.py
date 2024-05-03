from pymongo import MongoClient

# Provide the connection details
hostname = 'localhost'
port = 27017  # Default MongoDB port
username = 'skolaoffline'  # If authentication is required
password = 'admin'  # If authentication is required

# Create a MongoClient instance
client = MongoClient("mongodb+srv://skolaoffline:admin@cluster0.qy9ucuv.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

try:
    client.admin.command("ping")
    print("succesful")
except Exception:
    print("wrong")


db = client['skolaoffline']

# collection = db['users']

def insert(collection, data):
    db[collection].insert_one(data)
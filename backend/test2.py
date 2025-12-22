from pymongo import MongoClient
import config

client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
print(client.list_database_names())


import pandas as pd
from pymongo import MongoClient

# -----------------------------
# MongoDB Configuration
# -----------------------------
MONGO_URI = "mongodb://localhost:27017/"
DATABASE_NAME = "company_db"
COLLECTION_NAME = "employees"

# -----------------------------
# CSV File Path
# -----------------------------
csv_file = "employees.csv"

# -----------------------------
# Read CSV File
# -----------------------------
df = pd.read_csv(csv_file)

# Convert DataFrame to Dictionary Records
records = df.to_dict(orient="records")

# -----------------------------
# Connect to MongoDB
# -----------------------------
client = MongoClient(MONGO_URI)

# Select Database
db = client[DATABASE_NAME]

# Select Collection
collection = db[COLLECTION_NAME]

# -----------------------------
# Insert Data into MongoDB
# -----------------------------
result = collection.insert_many(records)

print(f"Inserted {len(result.inserted_ids)} records into MongoDB collection '{COLLECTION_NAME}'")

# -----------------------------
# Close Connection
# -----------------------------
client.close()

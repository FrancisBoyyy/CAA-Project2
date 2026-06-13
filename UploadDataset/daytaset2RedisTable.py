
import pandas as pd
import redis
import json

# -----------------------------
# Redis Configuration
# -----------------------------
REDIS_HOST = "localhost"
REDIS_PORT = 6379
REDIS_DB = 0

# -----------------------------
# CSV File Path
# -----------------------------
csv_file = "employees.csv"

# -----------------------------
# Redis Key Prefix
# -----------------------------
key_prefix = "employee"

# -----------------------------
# Connect to Redis
# -----------------------------
r = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True
)

# -----------------------------
# Read CSV File
# -----------------------------
df = pd.read_csv(csv_file)

# -----------------------------
# Store Each Row in Redis
# -----------------------------
for index, row in df.iterrows():
    
    # Convert row to dictionary
    employee_data = row.to_dict()

    # Create Redis key
    redis_key = f"{key_prefix}:{index + 1}"

    # Store as JSON string
    r.set(redis_key, json.dumps(employee_data))

    print(f"Inserted {redis_key}")

print("\nCSV data successfully imported into Redis.")

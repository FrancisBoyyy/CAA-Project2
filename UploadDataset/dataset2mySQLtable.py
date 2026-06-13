
import pandas as pd
import mysql.connector

# -----------------------------
# MySQL Database Configuration
# -----------------------------
host = "localhost"
user = "root"
password = "your_password"
database = "company_db"

# -----------------------------
# CSV File Path
# -----------------------------
csv_file = "employees.csv"

# -----------------------------
# MySQL Table Name
# -----------------------------
table_name = "employees"

# -----------------------------
# Read CSV File
# -----------------------------
df = pd.read_csv(csv_file)

# -----------------------------
# Connect to MySQL
# -----------------------------
conn = mysql.connector.connect(
    host=host,
    user=user,
    password=password,
    database=database
)

cursor = conn.cursor()

# -----------------------------
# Create Table Dynamically
# -----------------------------
columns = []

for col in df.columns:
    columns.append(f"`{col}` TEXT")

create_table_query = f"""
CREATE TABLE IF NOT EXISTS {table_name} (
    id INT AUTO_INCREMENT PRIMARY KEY,
    {', '.join(columns)}
)
"""

cursor.execute(create_table_query)

# -----------------------------
# Insert CSV Data into Table
# -----------------------------
for _, row in df.iterrows():
    
    placeholders = ", ".join(["%s"] * len(row))
    column_names = ", ".join([f"`{col}`" for col in df.columns])

    insert_query = f"""
    INSERT INTO {table_name}
    ({column_names})
    VALUES ({placeholders})
    """

    cursor.execute(insert_query, tuple(row))

# -----------------------------
# Commit Changes
# -----------------------------
conn.commit()

print(f"CSV data successfully imported into MySQL table '{table_name}'")

# -----------------------------
# Close Connection
# -----------------------------
cursor.close()
conn.close()

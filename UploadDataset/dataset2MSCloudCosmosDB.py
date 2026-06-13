import pandas as pd
from azure.cosmos import CosmosClient, exceptions

# ----------------------------------
# Azure Cosmos DB Configuration
# ----------------------------------
COSMOS_ENDPOINT = "https://your-account.documents.azure.com:443/"
COSMOS_KEY = "your_cosmos_primary_key"

DATABASE_NAME = "company_db"
CONTAINER_NAME = "employees"

# ----------------------------------
# CSV File Path
# ----------------------------------
csv_file = "employees.csv"

# ----------------------------------
# Connect to Azure Cosmos DB
# ----------------------------------
client = CosmosClient(COSMOS_ENDPOINT, credential=COSMOS_KEY)

# ----------------------------------
# Create Database if Not Exists
# ----------------------------------
database = client.create_database_if_not_exists(
    id=DATABASE_NAME
)

# ----------------------------------
# Create Container if Not Exists
# ----------------------------------
container = database.create_container_if_not_exists(
    id=CONTAINER_NAME,
    partition_key={"/path": "/employeeID"},
    offer_throughput=400
)

# ----------------------------------
# Read CSV File
# ----------------------------------
df = pd.read_csv(csv_file)

# ----------------------------------
# Insert CSV Data into Cosmos DB
# ----------------------------------
for index, row in df.iterrows():

    # Convert row to dictionary
    item = row.to_dict()

    # Cosmos DB requires an "id" field
    item["id"] = str(index + 1)

    # Insert item into container
    container.create_item(body=item)

    print(f"Inserted item {item['id']}")

print("\nCSV data successfully imported into Azure Cosmos DB.")

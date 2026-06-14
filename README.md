# Project Setup and Run Guide

This project is a **client-side encrypted employee database** backed by MongoDB.  
The client is responsible for bootstrap, encryption, indexing, decryption, integrity checks, and interactive queries.

## Requirements

- Java available in your path.
- Docker Engine running.
- The project dependencies placed in `src/lib`.
- MongoDB started through Docker before running the client.

---

## 1) Start MongoDB

Run this command from the **project root directory** (the folder **above** `/src`):

```bash
docker compose up -d
```

To stop the container later:

```bash
docker compose down
```

---

## 2) Prepare the project

Run the preparation script from the `/src` directory:

```bash
./prepare.sh
```

This script prepares the project for execution. In this project, `prepare.sh` is designed to be an easy and quick way to setup the project, and must be executed before launching the client.

If needed, make it executable first:

```bash
chmod +x prepare.sh
```

---

## 3) Run the client application

Still inside `/src`, start the application with:

```bash
java -cp ".:lib/*" client/App
```

> On Windows, the classpath separator may need to be `;` instead of `:`.

The application reads its configuration from `application.properties` and uses the client-side key/index directory configured there.

---

## 4) Clean the project

Run the clean script from the `/src` directory:

```bash
./clean.sh
```

This project’s `clean.sh` removes compiled classes and also clears the client index folder at:

```text
/src/client/index
```

If needed, make it executable first:

```bash
chmod +x clean.sh
```

---

## Configuration

The main configuration is stored in `application.properties`.

### MongoDB
```properties
mongo.uri=mongodb://admin:admin123@localhost:27017/?authSource=admin
mongo.database=company_db
mongo.collection=employees_encrypted
```

These values point the client to the local MongoDB instance started with Docker.

### Input dataset
```properties
employees.csv.path=Company-Employee.Database/Dataset-Emp-Database.csv
```

This is the CSV file used by the bootstrap command.

### Client-side key/index storage
```properties
keys.directory=client/index
```

This folder stores the generated client-side keys, OPE state, employee index, and snapshot output.

---

## How to use the application

After launching the client, you will see an interactive command interpreter.

Example:

```text
Employee DB client ready.
Decryption mode : OFF  (records returned as stored in the DB)
Type 'help' for commands.
> 
```

### Available commands

| Command | Description |
|---|---|
| `help` | Show the full command list |
| `exit` / `quit` | Close the client |
| `bootstrap` | Load the CSV dataset, encrypt it, and store it in MongoDB |
| `count` | Show how many employee records are stored |
| `find-id <employeeId>` | Search an employee by ID |
| `find-name <full name>` | Search an employee by full name |
| `find-dept <departmentId>` | List employees from a department |
| `salary-asc` | List employees ordered by salary, low to high |
| `salary-desc` | List employees ordered by salary, high to low |
| `age-asc` | List employees ordered by age, young to old |
| `age-desc` | List employees ordered by age, old to young |
| `highest-salary` | Show the employee with the highest salary |
| `oldest` | Show the oldest employee |
| `payroll <departmentId>` | Compute the total payroll for a department |
| `bonus <full name>` | Preview the 25% bonus for one employee |
| `bonuses` | Preview bonuses for all eligible employees |
| `apply-bonus <full name>` | Apply and persist the 25% bonus for one employee |
| `apply-bonuses` | Apply and persist bonuses for all eligible employees |
| `compare-salary Name A | Name B` | Compare the salaries of two employees |
| `toggle` | Switch between encrypted view and decrypted view |
| `snapshot [file]` | Export the encrypted DB contents to a snapshot file |

### Notes on interaction

- `bootstrap` is usually the first command to run after starting MongoDB.
- `toggle` only affects how query results are displayed in the client.
- `bonus` and `bonuses` are read-only previews.
- `apply-bonus` and `apply-bonuses` persist salary updates back to the database.
- `snapshot` writes a snapshot into:

```text
src/client/index/snapshots/
```

If no filename is provided, the application generates one automatically.

### Example session

```text
> bootstrap
Inserted 20 encrypted records.

> count
Stored employees: 20

> find-id EMP1001
{...}

> toggle
Decryption mode : ON  (records will be decrypted before display)

> highest-salary
{...}

> snapshot
Snapshot written to: /full/path/to/src/client/index/snapshots/encrypted-snapshot-2026-06-14.jsonl

> exit
Bye.
```

---

## Recommended run order

1. Start Docker:
   ```bash
   docker compose up -d
   ```
2. Go to `/src`
3. Run:
   ```bash
   ./prepare.sh
   ```
4. Start the client:
   ```bash
   java -cp ".:lib/*" client/App
   ```
5. Use `help` inside the app
6. When finished:
   ```bash
   ./clean.sh
   ```
   and then:
   ```bash
   docker compose down
   ```

---

## Project summary

The application bootstraps an encrypted employee database, stores it in MongoDB, and provides an interactive command-line interface for encrypted search, ordering, salary comparisons, payroll computation, bonus handling, and encrypted snapshots.

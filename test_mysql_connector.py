import mysql.connector

# Test MySQL connection
try:
    # Try to connect to a MySQL database (use localhost and root user for testing)
    connection = mysql.connector.connect(
        host="localhost",
        user="root",  # default MySQL username
        password=""  # default MySQL password (empty for XAMPP)
    )
    if connection.is_connected():
        print("Successfully connected to MySQL!")
    else:
        print("Failed to connect to MySQL.")
except mysql.connector.Error as err:
    print(f"Error: {err}")
finally:
    if connection.is_connected():
        connection.close()
        print("MySQL connection closed.")

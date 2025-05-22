import mysql.connector
import getPorts
import findMacAddress
import findVendor

# Connect to MySQL Database (XAMPP local server)
def connect_to_database():
    return mysql.connector.connect(
        host="localhost",      # Using XAMPP's MySQL server on localhost
        user="root",           # Default MySQL user in XAMPP
        password="",           # Default password is empty in XAMPP
        database="devicetype"  # My database name
    )

# Function to get device type based on open ports (from the database)
def get_device_type_from_db(open_ports):
    # Check if there are no open ports
    if not open_ports:
        # If there are no open ports, return a default unknown device type
        return "Unknown Device Type", "No open ports detected."

    db_connection = connect_to_database()
    cursor = db_connection.cursor()

    # Convert open_ports from list of dictionaries to just a list of port numbers
    open_ports_list = [port['port'] for port in open_ports]  # Extract port numbers

    # Build the query dynamically to check for matching device type based on open ports
    port_conditions = " OR ".join([f"FIND_IN_SET({port}, Ports)" for port in open_ports_list])
    
    query = f"""
    SELECT Device_type, Description
    FROM portlist
    WHERE {port_conditions};
    """
    
    try:
        cursor.execute(query)
        result = cursor.fetchone()  # Fetch the first matching result
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        result = None

    # Close the connection
    db_connection.close()

    if result:
        device_type, description = result
        return device_type, f"Matched ports: {open_ports_list}"

    # If no match found, return "Unknown Device Type"
    return "Unknown Device Type", "No description available"

# Function to guess the device type using vendor and open ports
def guess_type(vendor, ports):
    # Get the device type and description based on open ports
    device_type, description = get_device_type_from_db(ports)
    
    # You could also add more logic based on vendor or other characteristics if needed
    return device_type

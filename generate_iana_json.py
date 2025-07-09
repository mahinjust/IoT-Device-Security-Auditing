import json # Import JSON module for reading/writing JSON files

iana_dict = {} # Initialize an empty dictionary to store port/protocol -> service mappings

# Function to check if a line from the text file is valid and parseable
def is_valid_line(line):
    return (
        len(line) >= 40 # Line must be at least 40 characters long (basic length check)
        and line[0:15].strip() != ""  # The first 15 chars contain a non-empty service name
        and line[15:25].strip().isdigit()   # Characters 15-25 must contain a numeric port number
        and line[25:35].strip().lower() in ["tcp", "udp"]  # Characters 25-35 must be either "tcp" or "udp" (protocol)
    )

# Open the original IANA text file containing service-port info
with open("service-names-port-numbers.txt", encoding="utf-8") as f:
    for line in f: # Read the file line by line
        if is_valid_line(line): # Process only lines that match the expected format
            service = line[0:15].strip() # Extract service name (first 15 characters, trimmed)
            port = line[15:25].strip() # Extract port number (characters 15 to 25, trimmed)
            protocol = line[25:35].strip().lower() # Extract protocol (characters 25 to 35, trimmed and lowercase)
            key = f"{port}/{protocol}"  # Create key like "80/tcp" or "53/udp"
            if key not in iana_dict: # Avoid overwriting if key already exists
                iana_dict[key] = service  # Add mapping key -> service name to the dictionary

# After processing, write the resulting dictionary to a JSON file
with open("iana_services.json", "w") as f:
    json.dump(iana_dict, f, indent=2) # Save JSON with indentation for readability

print(f"Generated iana_services.json with {len(iana_dict)} entries.") # Print a message indicating how many entries were parsed and saved
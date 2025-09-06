# import os
# from urllib.parse import urlencode

# def load_config():
#     """
#     Loads database configuration from environment variables.

#     Returns:
#         dict: A dictionary containing database configuration.

#     Raises:
#         KeyError: If a required environment variable is missing.
#     """
#     config = {
#         'host': os.environ.get('DB_HOST', 'localhost'),  # Use 'localhost' from your phpMyAdmin
#         'user': os.environ.get('DB_USER', 'scronyqg_fac_user'),  # Replace with correct cPanel DB user
#         'password': os.environ.get('DB_PASSWORD', 'administrator12345@'),  # Ensure correctness
#         'database': os.environ.get('DB_NAME', 'scronyqg_fac'),  # Ensure this is the correct DB name
#         'port': int(os.environ.get('DB_PORT', 3306))  # Ensure the port is an integer
#     }

#      # Validate required environment variables
#     for key, value in config.items():
#         if value is None:
#             raise KeyError(f"Missing required environment variable: {key}")

#     return config

# def generate_db_uri():
#     """
#     Generates the database connection URI from environment variables.

#     Returns:
#         str: The constructed database connection URI.

#     Raises:
#         KeyError: If a required environment variable is missing.
#     """
#     config = load_config()

#     # Create connection URI with URL encoding for special characters
#     params = urlencode({
#         'charset': 'utf8'  # Optional: include charset for clarity
#     })

#     # Construct the database URI
#     db_uri = (
#         f"mysql+pymysql://{config['user']}:{config['password']}@"
#         f"{config['host']}:{config['port']}/{config['database']}?{params}"
#     )

#     return db_uri

# # Example usage:
# try:
#     db_uri = generate_db_uri()
#     print(db_uri)
# except KeyError as e:
#     print(f"Error: {e}")


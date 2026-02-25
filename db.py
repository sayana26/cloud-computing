import psycopg2
import os

def get_db_connection():
    # For Azure App Service (production)
    if os.getenv('AZURE_POSTGRESQL_HOST'):
        conn = psycopg2.connect(
            host=os.getenv('AZURE_POSTGRESQL_HOST'),
            database=os.getenv('AZURE_POSTGRESQL_NAME'),
            user=os.getenv('AZURE_POSTGRESQL_USER'),
            password=os.getenv('AZURE_POSTGRESQL_PASSWORD'),
            port='5432',
            sslmode='require'
        )
    # For local development
    else:
        conn = psycopg2.connect(
            host="localhost",
            database="data_wrangling_db",
            user="postgres",
            password="Sayana2002",
            port='5432'
        )
    return conn
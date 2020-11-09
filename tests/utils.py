import psycopg2
from os import environ as env

def rm_database():
    '''Removes all data from database
    :Author: Karlo Kegljevic <kkegljev@carnet.hr>
    '''
    try:
        ps_connection = psycopg2.connect(
            user=env.get("POSTGRE_USER"), 
            password=env.get("POSTGRE_PASSWORD"), 
            host=env.get("POSTGRE_IP"), 
            port="",
            database=env.get("POSTGRE_DATABASE"))
        cursor = ps_connection.cursor()
    except (Exception, psycopg2.DatabaseError) as e:
        print("Error connecting to database!", e)
        return
    try:
        cursor.callproc('drop_database_data', [])
        ps_connection.commit()
    except Exception as e:
        print(e)
    finally:
        if ps_connection:
            cursor.close()
            ps_connection.close()


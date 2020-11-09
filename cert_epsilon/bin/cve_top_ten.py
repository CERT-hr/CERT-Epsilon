import sys, psycopg2, logging
from os import environ as env
from dotenv import load_dotenv

def main():
    cursor = None
    try:
        ps_connection = psycopg2.connect(
            user=env.get("POSTGRE_USER"), 
            password=env.get("POSTGRE_PASSWORD"), 
            host=env.get("POSTGRE_IP"), 
            port="5432",
            database=env.get("POSTGRE_DATABASE"))
        cursor = ps_connection.cursor()
    except psycopg2.DatabaseError as e:
        logging.critical('CRITICAL DATABASE ERROR IN cve_top_ten.py, CANT CONNECT TO THE DATABASE -> [%s]' % (e,))
        sys.exit(1)
    except Exception as e:
        logging.error('Unknown database error in cve_top_ten.py while connecting to the database -> [%s]' % (e,))
        sys.exit(1)

    try:
        cursor.execute("DELETE FROM tbl_cve_top_ten", [])
        cursor.execute("""
                SELECT v.name, COUNT(DISTINCT c.cve_id) AS "vulns" FROM tbl_cve AS c
	            LEFT JOIN xref_cve_product AS xf ON xf.id_cve=c.cve_id
                LEFT JOIN tbl_product AS p ON p.product_id=id_product
	            LEFT JOIN tbl_vendor as v ON v.vendor_id=p.id_vendor
	            WHERE c.published_date >= CURRENT_DATE - interval '7 days' AND v.name IS NOT NULL                                                                                                                                                               GROUP BY v.name
	            ORDER BY "vulns" DESC, v.name DESC
	            lLIMIT 10;
                """, [])
        for cve in cursor.fetchall():
            cursor.execute("""
                INSERT INTO tbl_cve_top_ten(id_cve) VALUES ('%s');
            """ % (cve[0])) # well isn't this a nice false positive
    except psycopg2.IntegrityError as e:
        logging.error("Exception raised in cve_top_ten.py when the relational integrity of the database is affected, e.g. a foreign key check fails.")
        ps_connection.rollback()
        sys.exit(1)
    except psycopg2.ProgrammingError as e:
        logging.error("Exception raised in cve_top_ten.py for programming errors, e.g. table not found or already "+ 
        "exists, syntax error in the SQL statement, wrong number of parameters specified, "+
        "function doesnt exist?")
        ps_connection.rollback()
        sys.exit(1)
    except Exception as e:
        logging.error('Unknown database error in cve_top_ten.py while executing function -> [%s]' % (e,))
        ps_connection.rollback()
        sys.exit(1)
    else:
        ps_connection.commit()
    finally:
        if ps_connection:
            cursor.close()
            ps_connection.close()


if __name__ == '__main__':
    load_dotenv()
    log_level = env.get("LOGGING")
    if log_level=='CRITICAL':
        logging.basicConfig(level=logging.CRITICAL)
    else:
        logging.basicConfig(level=logging.DEBUG)
    main()
else:
    logging.info("cve_top_ten.py is used as a standalone executable!")
    sys.exit(1)    

import psycopg2, logging, traceback
from datetime import datetime as dt
from os import environ as env
from dotenv import load_dotenv
from flask_babel import _
import re

class db_handler:

    def handle_connection(f):
        '''Used as a decorator, handles connection to the database, every function decorated with this 
        decorator needs to have cursor=None as parameter, and can use it as an active connection to the
        database
        
        :return: If any exception is thrown while handling the database connection, commiting to the database
            or closing connection, handle_connection will return False

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        def wrapper(*args, **kwargs):
            try:
                ps_connection = psycopg2.connect(
                    user=env.get("POSTGRE_USER"), 
                    password=env.get("POSTGRE_PASSWORD"), 
                    host=env.get("POSTGRE_IP"), 
                    port=env.get("POSTGRE_PORT"),
                    database=env.get("POSTGRE_DATABASE"))
                cursor = ps_connection.cursor()
            except psycopg2.DatabaseError as e:
                logging.critical('CRITICAL DATABASE ERROR, CANT CONNECT TO THE DATABASE -> [%s]' % (e,))
                if env.get("LOGGING") == 'INFO':
                    traceback.print_exc()
                r = False
                return
            except Exception as e:
                logging.error('Unknown database error while connecting to the database -> [%s]' % (e,))
                if env.get("LOGGING") == 'INFO':
                    traceback.print_exc()
                r = False
                return

            r = None
            try:
                r = f(*args,*kwargs, cursor=cursor)
            except psycopg2.IntegrityError as e:
                r = False
                logging.error("Exception raised when the relational integrity of the database is affected, e.g. a foreign key check fails.")
                if env.get("LOGGING") == 'INFO':
                    traceback.print_exc()
                ps_connection.rollback()
                return
            except psycopg2.ProgrammingError as e:
                r = False
                logging.error("Exception raised for programming errors, e.g. table not found or already "+ 
                "exists, syntax error in the SQL statement, wrong number of parameters specified, "+
                "function doesnt exist?")
                logging.error(e)
                if env.get("LOGGING") == 'INFO':
                    traceback.print_exc()
                ps_connection.rollback()
                return
            except Exception as e:
                logging.error('Unknown database error while executing function -> [%s]' % (e,))
                if env.get("LOGGING") == 'INFO':
                    traceback.print_exc()
                r = False
                ps_connection.rollback()
                return
            else:
                ps_connection.commit()
            finally:
                if ps_connection:
                    cursor.close()
                    ps_connection.close()
                return r
        return wrapper
    

    @staticmethod
    @handle_connection
    def get_cve(keyword, cursor=None):
        '''Fetches cve from the database

        :param keyword
        :return: Dictionary with cve's attributes as keys
        :rtype: dict
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        tmp = keyword.strip()
        if re.search(r'CVE-\d{4}-\d{4,7}', tmp.upper()):
            cursor.callproc('get_cve',
                    [keyword, ])
        else:
            return {}
        r = {}
        try:
            r = cursor.fetchone()
            r = {
                    "cve_id": r[0],
                    "description": r[1],
                    "cvss": r[2],
                    "published_date": r[3],
                    "reference_links": r[4],
                    "exploitability_score": r[5],
                    "impact_score": r[6],
                    "severity": r[7],
                    "cvss_access_vector": r[8],
                    "cvss_vector_string": r[9],
                    "cvss_access_complexity": r[10],
                    "cvss_authentication": r[11],
                    "cvss_confidentiality_impact": r[12],
                    "cvss_integrity_impact": r[13],
                    "cvss_availability_impact": r[14],
                    "last_modified_date": r[15]
                }
        except (IndexError, TypeError):
            return {}
        return r
    
    @staticmethod
    @handle_connection
    def get_cves(keyword, cursor=None):
        '''Fetches cves from the database

        :param keyword
        :return: List of dictionaries with cve's attributes as keys
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        tmp = keyword.strip()
        if re.search(r'CVE-\d{4}-\d{4,7}', tmp.upper()):
            cursor.callproc('get_cve', 
                    [keyword, ])
        elif keyword==".":
            try: 
                cursor.execute("SELECT * FROM tbl_cve ORDER BY last_modified_date DESC, published_date DESC, cve_id DESC", [])
            except Exception:
                return [] 
        else:
            cursor.callproc('get_cve_by_description', 
                [keyword, ])
         
        cves = []
        try:
            for r in cursor.fetchall():
                cves.append({
                        "cve_id": r[0],
                        "description": r[1],
                        "cvss": r[2],
                        "published_date": r[3],
                        "reference_links": r[4],
                        "exploitability_score": r[5],
                        "impact_score": r[6],
                        "severity": r[7],
                        "cvss_access_vector": r[8],
                        "cvss_vector_string": r[9],
                        "cvss_access_complexity": r[10],
                        "cvss_authentication": r[11],
                        "cvss_confidentiality_impact": r[12],
                        "cvss_integrity_impact": r[13],
                        "cvss_availability_impact": r[14],
                        "last_modified_date": r[15]
                    })
        except (IndexError, TypeError):
            return []
        return cves
    
    @staticmethod
    @handle_connection
    def get_cve_top_ten(cursor=None):
        '''Fetches top 10 cves from the database

        :return: List of dictionaries with cve's attributes as keys
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_top_ten_cve', 
            [])
         
        cves = []
        try:
            for r in cursor.fetchall():
                cves.append({
                        "cve_id": r[0],
                        "description": r[1],
                        "cvss": r[2],
                        "published_date": r[3],
                        "reference_links": r[4],
                        "exploitability_score": r[5],
                        "impact_score": r[6],
                        "severity": r[7],
                        "cvss_access_vector": r[8],
                        "cvss_vector_string": r[9],
                        "cvss_access_complexity": r[10],
                        "cvss_authentication": r[11],
                        "cvss_confidentiality_impact": r[12],
                        "cvss_integrity_impact": r[13],
                        "cvss_availability_impact": r[14],
                        "last_modified_date": r[15]
                    })
        except (IndexError, TypeError):
            return []
        return cves

    @staticmethod
    @handle_connection
    def get_capec(capec_id, cursor=None):
        '''Fetches CAPEC from database

        :param capec_id
        :return: Dictionary with keys capec_id, name, description, prerequisites and mitigations
        :rtype: dict 
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_capec', 
                [capec_id, ])
        r = {}
        try:
            r = cursor.fetchone()
            r = {
                    'capec_id': r[0],
                    'name': r[1],
                    'description': r[2],
                    'prerequisites': r[3],
                    'mitigations': r[4].split('|') if '|' in r[4] else r[4]
                }
        except (IndexError, TypeError):
            return {}
        return r
    
    @staticmethod
    @handle_connection
    def get_capec_for_cwe(cwe_id, cursor=None):
        '''Fetches all CAPECs related to the specific CWE from the database

        :param capec_id
        :return: Dictionary with keys capec_id, name, description, prerequisites and mitigations
        :rtype: dict 
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_capec_for_cwe', 
                [cwe_id, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        'capec_id': r[0],
                        'name': r[1],
                        'description': r[2],
                        'prerequisites': r[3],
                        'mitigations': r[4].split('|') if '|' in r[4] else r[4]
                    })
        except (IndexError, TypeError):
            return []
        return ret

    @staticmethod
    @handle_connection
    def get_cwe(cwe_id, cursor=None):
        '''Fetches CWE from database

        :param cwe_id 
        :return: Dictionary with keys cwe_id, name, description
        :rtype: dict 
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_cwe', 
                [cwe_id, ])
        r = {}
        try:
            r = cursor.fetchone()
            r = {
                    'cwe_id': r[0],
                    'name': r[1],
                    'description': r[2]
                }
        except (IndexError, TypeError):
            return {}
        return r
    
    @staticmethod
    @handle_connection
    def get_cwes(keyword, cursor=None):
        '''Fetches cwes from the database

        :param keyword
        :return: List of dictionaries with cwe's attributes as keys
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        tmp = keyword.strip()
        if re.search(r'CWE-\d{1,6}', tmp.upper()):
            cursor.callproc('get_cwe', 
                    [keyword, ])
        else:
            cursor.callproc('get_cwe_by_description', 
                [keyword, ])
         
        cwes = []
        try:
            for r in cursor.fetchall():
                cwes.append({
                        'cwe_id': r[0],
                        'name': r[1],
                        'description': r[2]
                    })
        except (IndexError, TypeError):
            return [{}]
        return cwes

    @staticmethod
    @handle_connection
    def get_vendor(vendor_name, cursor=None):
        '''Fetches vendor for given vendor name

        :return: Dictionary with keys name and vendor_id 
        :rtype: dict
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_vendor', 
                [vendor_name, ])
        ret = None
        try:
            r = cursor.fetchone()
            ret = {'vendor_id': r[0], 'name': r[1]}
        except (IndexError, TypeError):
            return {}
        return ret

    @staticmethod
    @handle_connection
    def get_vendor_by_id(vendor_id, cursor=None):
        '''Fetches vendor for given vendor id

        :return: Dictionry with keys vendor_id, name
        :rtype: dict
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_vendor_by_id',
                [vendor_id, ])
        ret = []
        try:
            r = cursor.fetchone()
            ret = {
                    'vendor_id': r[0],
                    'name': r[1]
                }
        except (IndexError, TypeError):
            return {}
        return ret
    
    @staticmethod
    @handle_connection
    def get_vendors(keyword, cursor=None):
        '''Fetches vendor for given keyword 

        :return: Dictionary with keys name and vendor_id 
        :rtype: dict
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_vendors', 
                [keyword, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({'vendor_id': r[0], 'name': r[1]})
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_all_vendors(cursor=None):
        '''Fetches all vendors from the database

        :return: List of dictionaries with keys name and vendor_id 
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_all_vendors', 
                [])
        ret = [] 
        try:
            for r in cursor.fetchall():
                ret.append({
                        'vendor_id': r[0], 
                        'name': r[1]
                    })
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_vendors_in_range(start, limit, cursor=None):
        '''Fetches vendors in range from the database

        :return: List of dictionaries with keys name and vendor_id 
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_vendors_in_range', 
                [start, limit])
        ret = [] 
        try:
            for r in cursor.fetchall():
                ret.append({
                        'vendor_id': r[0], 
                        'name': r[1]
                    })
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_product(product_name, cursor=None):
        '''Fetches product for given product name

        :return: Dictionry with keys product_id, name, id_vendor 
        :rtype: dict
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_product', 
                [product_name, ])
        ret = []
        try:
            r = cursor.fetchone()
            ret = {
                    'product_id': r[0],
                    'name': r[1],
                    'id_vendor': r[2]
                }
        except (IndexError, TypeError):
            return {}
        return ret

    @staticmethod
    @handle_connection
    def get_product_by_id(product_id, cursor=None):
        '''Fetches product for given product id

        :return: Dictionry with keys product_id, name, id_vendor
        :rtype: dict
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_product_by_id',
                [product_id, ])
        ret = []
        try:
            r = cursor.fetchone()
            ret = {
                    'product_id': r[0],
                    'name': r[1],
                    'id_vendor': r[2]
                }
        except (IndexError, TypeError):
            return {}
        return ret
    
    @staticmethod
    @handle_connection
    def get_cwe_for_cve(cve_id, cursor=None):
        '''Fetches all CWE's for given cve 

        :param cve_id 
        :return: List of cwe dictionaries with keys cwe_id, name, description
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_cwe_for_cve', 
                [cve_id, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        'cwe_id': r[0],
                        'name': r[1],
                        'description': r[2]
                    })
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_all_cwe(cursor=None):
        '''Fetches all CWE's for the database

        :return: List of cwe dictionaries with keys cwe_id, name, description
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_all_cwe', 
                [ ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        'cwe_id': r[0],
                        'name': r[1],
                        'description': r[2]
                    })
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_products_for_vendor(vendor_name, cursor=None):
        '''Fetches all products for given vendor name 

        :return: List of product dictionaries with keys product_id, name, vendor_id
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_products_for_vendor', 
                [vendor_name, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        'product_id': r[0],
                        'name': r[1],
                        'id_vendor': r[2]
                    })
        except (IndexError, TypeError):
            return []
        return ret

    @staticmethod
    @handle_connection
    def get_cve_in_range(start, limit, cursor=None):
        '''Fetches range of CVEs 

        :param start
        :param limit
        :return: List of cve dictionaries 
        :rtype: list(dict)
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_cve_in_range', 
                [start, limit])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        "cve_id": r[0],
                        "description": r[1],
                        "cvss": r[2],
                        "published_date": r[3],
                        "reference_links": r[4],
                        "exploitability_score": r[5],
                        "impact_score": r[6],
                        "severity": r[7],
                        "cvss_access_vector": r[8],
                        "cvss_vector_string": r[9],
                        "cvss_access_complexity": r[10],
                        "cvss_authentication": r[11],
                        "cvss_confidentiality_impact": r[12],
                        "cvss_integrity_impact": r[13],
                        "cvss_availability_impact": r[14],
                        "last_modified_date": r[15]
                    })
        except (IndexError, TypeError):
            return []
        return ret
    
    @staticmethod
    @handle_connection
    def get_cve_count(cursor=None):
        '''Fetches count of CVEs

        :return: cve count 
        :rtype: int
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            cursor.callproc('get_cve_count',[])
            return cursor.fetchone()[0]
        except Exception:
            return 0
        return 0
        
    @staticmethod
    @handle_connection
    def get_vendor_count(cursor=None):
        '''Fetches count of vendors

        :return: vendor count
        :rtype: int
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            cursor.callproc('get_vendor_count',[])
            return cursor.fetchone()[0]
        except Exception:
            return 0
        return 0

    @staticmethod
    @handle_connection
    def get_operating_system_types(cursor=None):
        '''Fetches type list from operation system table

        :return: List of dictionaries with operation system types
        :rtype: list(dict)
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_all_operating_system_types',
                [])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append(r[0])
        except (IndexError, TypeError):
            return {}
        return ret

    @staticmethod
    @handle_connection
    def get_operation_system_by_type(os_type, cursor=None):
        '''Fetches all dinstict operating systems for given type

        :return: List of distinct operating systems
        :rtype: list(dict)
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_operating_systems_for_type',
                [os_type, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append(r[0])
        except (IndexError, TypeError):
            return [{}]
        return ret

    @staticmethod
    @handle_connection
    def get_product_ids_from_name(os_name, cursor=None):
        '''Fetches all product ids form tbl_operating_system for given name

        :return: List of product ids
        :rtype: list(dict)
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_product_ids_for_operating_system_name',
                [os_name, ])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append(r[0])
        except (IndexError, TypeError):
            return [{}]
        return ret

    @staticmethod
    @handle_connection
    def get_all_users(cursor=None):
        '''Fetches all users from the database

        :return: List of dictionaries with keys user_id and email
        :rtype: list(dict)
        :Author: Renato Kaćera <kkegljev@carnet.hr>
        '''
        cursor.callproc('get_all_users',
                [])
        ret = []
        try:
            for r in cursor.fetchall():
                ret.append({
                        'user_id': r[0],
                        'email': r[1]
                    })
        except (IndexError, TypeError):
            return []
        return ret

    @staticmethod
    @handle_connection
    def get_user_subscriptions(user_id, cursor=None):
        '''Fetches all subscriptions for given user id

        :return: List of subscriptions
        :rtype: list(dict) or []
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_user_subscriptions',
                [user_id, ])
        ret = []
        #try:
        for r in cursor.fetchall():
            product = db_handler.get_product_by_id(r[6])["name"] if r[6] is not None else _('Not set')
            cvss = r[2] if r[2] is not None else _('Not set')
            ret.append({
                    'id': r[0],
                    'vendor': db_handler.get_vendor_by_id(r[7])["name"],
                    'product': product,
                    'cvss': cvss
                })
        # except (IndexError, TypeError):
        #     return []
        return ret


    @staticmethod
    @handle_connection
    def get_user(email, cursor=None):
        '''Fetches user_id for given email

        :return: user_id
        :rtype: int or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('select_user',
                [email, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def get_subscription_by_id(id, cursor=None):
        '''Fetches subscription for given sub id

        :return: subscription
        :rtype: dict or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('get_subscription_by_id',
                [id, ])
        r = {}
        try:
            r = cursor.fetchone()
            r = {
                    'confirmed': r[4]
                }
        except (IndexError, TypeError):
            return {}
        return r
    
    @staticmethod
    @handle_connection
    def get_user_cves(user_id, cursor=None):
        '''Returns all cves for email for given user_id

        :param user_id
        :return list of dictionaries 
        :rtype: 
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        :Author: Renato Kacera <rkacera@carnet.hr>
        '''
        cves = []
        try:
            # get user all subscriptions
            cursor.callproc('get_user_subscriptions', [user_id])
            subscriptions = cursor.fetchall()
            # get cves for each subscription
            for subscription in subscriptions:
                cursor.callproc('get_user_daily_cves', [subscription[0]])
                for r in cursor.fetchall():
                    cves.append({
                            "vendor": db_handler.get_vendor_by_id(subscription[7])["name"],
                            "product": db_handler.get_product_by_id(subscription[6])["name"],
                            "cve_id": r[0],
                            "description": r[1],
                            "cvss": r[2],
                            "published_date": r[3],
                            "reference_links": r[4],
                            "exploitability_score": r[5],
                            "impact_score": r[6],
                            "severity": r[7],
                            "cvss_access_vector": r[8],
                            "cvss_vector_string": r[9],
                            "cvss_access_complexity": r[10],
                            "cvss_authentication": r[11],
                            "cvss_confidentiality_impact": r[12],
                            "cvss_integrity_impact": r[13],
                            "cvss_availability_impact": r[14],
                            "last_modified_date": r[15]
                        })
            cves = list({v['cve_id']:v for v in cves}.values())
        except Exception as e:
            return [{}]
        return list(cves)

    @staticmethod
    @handle_connection
    def insert_cve(
            cve_id, 
            description, 
            cvss, 
            published_date, 
            last_modified_date, 
            reference_links=None,
            exploitability_score=None,
            impact_score=None,
            severity=None,
            cvss_access_vector=None,
            cvss_vector_string=None,
            cvss_access_complexity=None,
            cvss_authentication=None,
            cvss_confidentiality_impact=None,
            cvss_integrity_impact=None,
            cvss_availability_impact=None,
            cursor=None):
        '''Inserts CVE in database

        :param cve_id
        :param description
        :param cvss
        :param published_date
        :param last_modified_date
        :param reference_links, optional
        :param exploitability_score, optional
        :param impact_score, optional
        :param severity, optional
        :param cvss_access_vector, optional
        :param cvss_vector_string, optional
        :param cvss_access_complexity, optional
        :param cvss_authentication, optional
        :param cvss_confidentiality_impact, optional
        :param cvss_integrity_impact, optional
        :param cvss_availability_impact, optional
        :return: cve_id of inserted cve or None
        :rtype: string or None
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_cve',
                {
                    "cve_id": cve_id,
                    "description": description,
                    "cvss": cvss,
                    "published_date": published_date,
                    "last_modified_date": last_modified_date,
                    "reference_links": reference_links,
                    "exploitability_score": exploitability_score,
                    "impact_score": impact_score,
                    "severity": severity,
                    "cvss_access_vector": cvss_access_vector,
                    "cvss_vector_string": cvss_vector_string,
                    "cvss_access_complexity": cvss_access_complexity,
                    "cvss_authentication": cvss_authentication,
                    "cvss_confidentiality_impact": cvss_confidentiality_impact,
                    "cvss_integrity_impact": cvss_integrity_impact,
                    "cvss_availability_impact": cvss_availability_impact 
                })
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        if r != cve_id:
            return None
        else:
            return r

    @staticmethod
    @handle_connection
    def update_cve(
            cve_id,
            description, 
            cvss, 
            published_date, 
            last_modified_date, 
            reference_links=None,
            exploitability_score=None,
            impact_score=None,
            severity=None,
            cvss_access_vector=None,
            cvss_vector_string=None,
            cvss_access_complexity=None,
            cvss_authentication=None,
            cvss_confidentiality_impact=None,
            cvss_integrity_impact=None,
            cvss_availability_impact=None,
            cursor=None):
        '''updates CVE in database

        :param cve_id
        :param description
        :param cvss
        :param published_date
        :param last_modified_date
        :param reference_links, optional
        :param exploitability_score, optional
        :param impact_score, optional
        :param severity, optional
        :param cvss_access_vector, optional
        :param cvss_vector_string, optional
        :param cvss_access_complexity, optional
        :param cvss_authentication, optional
        :param cvss_confidentiality_impact, optional
        :param cvss_integrity_impact, optional
        :param cvss_availability_impact, optional
        :return: False if failted to update, True otherwise
        :rtype: boolean
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            cursor.callproc('update_cve',
                    {
                        "cve_id_": cve_id,
                        "description_": description,
                        "cvss_": cvss,
                        "published_date_": published_date,
                        "last_modified_date_": last_modified_date,
                        "reference_links_": reference_links,
                        "exploitability_score_": exploitability_score,
                        "impact_score_": impact_score,
                        "severity_": severity,
                        "cvss_access_vector_": cvss_access_vector,
                        "cvss_vector_string_": cvss_vector_string,
                        "cvss_access_complexity_": cvss_access_complexity,
                        "cvss_authentication_": cvss_authentication,
                        "cvss_confidentiality_impact_": cvss_confidentiality_impact,
                        "cvss_integrity_impact_": cvss_integrity_impact,
                        "cvss_availability_impact_": cvss_availability_impact 
                    })
        except Exception:
            traceback.print_exc()
            return False
        else:
            return True        

    @staticmethod
    @handle_connection
    def insert_capec(capec_id, name, description, prerequisites, mitigations, cursor=None):
        '''Inserts CAPEC in database

        :param capec_id
        :param name
        :param description
        :param prerequisites
        :param mitigations
        :return: capec_id of inserted capec or None
        :rtype: string or None
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_capec', 
                [capec_id, name, description, prerequisites, mitigations])
        r = None
        try:
            r = cursor.fetchone()[0] # get first row and first col
        except IndexError:
            return None
        if r != capec_id:
            return None
        else:
            return r

    @staticmethod
    @handle_connection
    def insert_cwe(cwe_id, name, description, cursor=None):
        '''Inserts CWE in database

        :param cwe_id 
        :param name
        :param description
        :return: cwe_id of inserted cwe or None
        :rtype: string or none
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_cwe', [cwe_id, name, description,])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        if r != cwe_id:
            return None
        else:
            return r
    
    @staticmethod
    @handle_connection
    def insert_xref_cve_cwe(cve_id, cwe_id, cursor=None):
        '''Inserts cve and cwe id in the xref_cve_cwe table

        :param cve_id
        :param cwe_id
        :return True or False if inserted
        :rtype: bool
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_cve_cwe', [cve_id, cwe_id,])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return False
        return True
    
    @staticmethod
    @handle_connection
    def insert_xref_cwe_capec(cwe_id, capec_id, cursor=None):
        '''Inserts cwe and capec id in the xref_cwe_capec table

        :param cwe_id
        :param capec_id
        :return True or False if inserted
        :rtype: bool
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_cwe_capec', [cwe_id, capec_id,])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return False
        return True
    
    @staticmethod
    @handle_connection
    def insert_xref_cve_product(cve_id, product_id, cursor=None):
        '''Inserts cve and product id in the xref_cve_product table

        :param cve_id
        :param product_id
        :return True or False if inserted
        :rtype: bool
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_cve_product', [cve_id, product_id,])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return False
        return True
    
    @staticmethod
    @handle_connection
    def insert_product(name, id_vendor, cursor=None):
        '''Inserts product in tbl_product

        :param name
        :param id_vendor
        :return product id of inserted product or None
        :rtype: int or None
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_product', [name, id_vendor])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r
    
    @staticmethod
    @handle_connection
    def insert_vendor(name, cursor=None):
        '''Inserts vendor in tbl_vendor

        :param name
        :return vendor id of inserted vendor or None
        :rtype: int or None
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_vendor', [name, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r
    
    @staticmethod
    @handle_connection
    def insert_operating_system(name, id_product, os_type, cursor=None):
        '''Inserts operating system in tbl_operating_system

        :param name
        :param id_product
        :param os_type
        :return operating system id of inserted OS or None
        :rtype: int or None
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        cursor.callproc('insert_operating_system', [name, id_product, os_type,])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def insert_user(email, cursor=None):
        '''Insert user in tbl_user

        :param name
        :return user id of inserted user or None
        :rtype: int or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('insert_user', [email, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def insert_subscription(custom_regex, cvss, confirmed, id_user, id_product, id_vendor, cursor=None):
        '''Inserts subscription in database tbl_subscription

        :param capec_id
        :param name
        :param description
        :param prerequisites
        :param mitigations
        :return: subscription_id of inserted subscription or None
        :rtype: int or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('insert_subscription',
                [custom_regex, cvss, confirmed, id_user, id_product, id_vendor])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def bulk_insert_products(product_list, cursor=None):
        '''Inserts list of products 

        :param product_list
        :return Number of inserted products. If the database already has some 
        of the products in the list, it will insert only the ones that arent stored.
        :rtype: int
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        c = 0
        for p in product_list:
            try:
                cursor.callproc('insert_product', [p['name'], p['id_vendor'] ])
                c+=1
            except Exception as e:
                logging.warning('Exception while bulk inserting products %s' % (e,))
                logging.warning('product list is [%s]' % ('|'.join(product_list),))
                continue
        return c
    
    @staticmethod
    @handle_connection
    def bulk_insert_vendors(vendor_list, cursor=None):
        '''Inserts list of vendors

        :param vendor_list
        :return Number of inserted vendors. If the database already has some 
        of the vendors in the list, it will insert only the ones that arent stored.
        :rtype: int
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        c = 0
        for v in vendor_list:
            try:
                cursor.callproc('insert_vendor', [v, ])
                c+=1
            except Exception as e:
                logging.warning('Exception while bulk inserting vendors %s' % (e,))
                logging.warning('vendor list is [%s]' % ('|'.join(vendor_list),))
                continue
        return c
    
    @staticmethod
    @handle_connection
    def get_vendor_cves(vendor_name, last_week=False, cursor=None):
        '''Returns number of cves for a given vendor, if True is passed it will return last weeks cve count

        :param vendor_name
        :param last_week
        :return Number of cves
        :rtype: int
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            cursor.callproc('get_vendor_cve_count', {'vendor_name':vendor_name, 'last_week':last_week})
        except Exception as e:
            print(e)
            traceback.print_exc()
            return 0
        return cursor.fetchone()[0]
    
    @staticmethod
    @handle_connection
    def get_vendor_top_ten(weekly=False, cursor=None):
        '''Returns top ten vendors this week or all time depending if string "weekly" is given as weekly parameter

        :param weekly
        :return list of dictionaries containing name and vulns (count of vulns for the vendor)
        :rtype: 
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        ret = [{}]
        try:
            if weekly == "weekly":
                cursor.callproc('get_top_ten_vendor_weekly', [])
            else:
                cursor.callproc('get_top_ten_vendor', [])
            for row in cursor.fetchall():
                ret.append({'name': row[0], 'vulns':row[1]})
        except Exception as e:
            print(e)
            traceback.print_exc()
        return ret
   

    @staticmethod
    @handle_connection
    def filter_cves(filters, cursor=None):
        '''Filters cves and returns filtered cves with given filter
         
        :param filters - ImmutableMultiDict with 
        (date_mode AND date_start AND/OR date_end) AND/OR (cvss_mode AND cvss) AND/OR os AND/OR vendor
        :return filtered cves
        :rtype: list of cve dictionaries
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        # prepare filter booleans
        date_filter   = True if filters.get('date_mode')  else False
        cvss_filter   = True if filters.get('cvss_mode')  else False
        os_filter     = True if filters.getlist('os')     else False
        vendor_filter = True if filters.getlist('vendor') else False
        if not (date_filter or cvss_filter or os_filter or vendor_filter):
            return []
        
        os_cves = []
        try:
            if filters.get('os'):
                os_cves = set()
                for os in filters.getlist('os'):
                    cursor.callproc('get_cve_by_os', [os, ])
                    os_cves.add(frozenset([cve[0] for cve in cursor.fetchall()]))
                os_cves = frozenset.intersection(*os_cves)
        except Exception:
            traceback.print_exc()
            logging.critical("Something is broken with getting cves by os in db_handler.filter method")
            return []

        vendor_cves = []
        try:
            if filters.get('vendor'):
                vendor_cves = set()
                for vendor in filters.getlist('vendor'):
                    cursor.callproc('get_cve_by_vendor', [vendor, ])
                    vendor_cves.add(frozenset([cve[0] for cve in cursor.fetchall()]))
                vendor_cves = frozenset.intersection(*vendor_cves)
        except Exception:
            logging.critical("Something is broken with getting cves by vendor in db_handler.filter method")
            return []

        try: 
            cursor.execute("SELECT * FROM tbl_cve ORDER BY last_modified_date DESC, published_date DESC, cve_id DESC", []) # get all cves
        except Exception:
            logging.critical("Something is broken with getting all cves in filter method")
            return []
        cves = []
        try:
            
            for r in cursor.fetchall():
                passed_date = True
                passed_cvss = True
                passed_os = True
                passed_vendor = True
                if date_filter:
                    passed_date = False
                    if filters.get('date_mode') == 'from' and filters.get('date_start') and r[3] >= dt.strptime(filters.get('date_start'), '%Y-%m-%d'):
                        passed_date = True
                    elif filters.get('date_mode') == 'until' and filters.get('date_end') and r[3] <= dt.strptime(filters.get('date_end'),'%Y-%m-%d'):
                        passed_date = True
                    elif filters.get('date_mode') == 'between' \
                            and filters.get('date_start') \
                            and filters.get('date_end') \
                            and r[3] >= dt.strptime(filters.get('date_start'), '%Y-%m-%d') \
                            and r[3] <= dt.strptime(filters.get('date_end'), '%Y-%m-%d'):
                        passed_date = True
                
                if cvss_filter:
                    passed_cvss = False
                    if filters.get('cvss_mode') == 'more_than' and str(filters.get('cvss')).isdigit() and float(r[2]) > float(filters.get('cvss')):
                        passed_cvss = True
                    elif filters.get('cvss_mode') == 'less_than' and str(filters.get('cvss')).isdigit() and float(r[2]) < float(filters.get('cvss')):
                        passed_cvss = True
                    elif filters.get('cvss_mode') == 'equal' and str(filters.get('cvss')).isdigit() and float(r[2]) == float(filters.get('cvss')):
                        passed_cvss = True
                
                if os_filter:
                    passed_os = False
                    if filters.get('os') and r[0] in os_cves:
                        passed_os = True
                        
                if vendor_filter:
                    passed_vendor = False
                    if filters.get('vendor') and r[0] in vendor_cves:
                        passed_vendor = True

                if passed_date and passed_cvss and passed_os and passed_vendor:
                    cves.append({
                            "cve_id": r[0],
                            "description": r[1],
                            "cvss": r[2],
                            "published_date": r[3],
                            "reference_links": r[4],
                            "exploitability_score": r[5],
                            "impact_score": r[6],
                            "severity": r[7],
                            "cvss_access_vector": r[8],
                            "cvss_vector_string": r[9],
                            "cvss_access_complexity": r[10],
                            "cvss_authentication": r[11],
                            "cvss_confidentiality_impact": r[12],
                            "cvss_integrity_impact": r[13],
                            "cvss_availability_impact": r[14],
                            "last_modified_date": r[15]
                        })
        except Exception:
            if env.get("LOGGING") == "INFO":
                traceback.print_exc()
            return []
        return cves

    @staticmethod
    @handle_connection
    def confirm_subscription(id, cursor=None):
        '''Confirm subscription by given id

        :return: void
        :rtype: void or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('confirm_subscription',
                [id, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def delete_subscription(id, cursor=None):
        '''Delete subscription by given id

        :return: void
        :rtype: void or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('delete_subscription',
                [id, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

    @staticmethod
    @handle_connection
    def delete_user(email, cursor=None):
        '''Delete user by email

        :return: void
        :rtype: void or None
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        cursor.callproc('delete_user',
                [email, ])
        r = None
        try:
            r = cursor.fetchone()[0]
        except IndexError:
            return None
        return r

if __name__ == '__main__':
    logging.info("db_handler is used only as a module")
else:
    load_dotenv()
    log_level = env.get("LOGGING")
    if log_level == 'CRITICAL':
        logging.basicConfig(level = logging.CRITICAL)
    elif log_level == 'INFO':
        logging.basicConfig(level = logging.INFO)
    else:
        logging.basicConfig(level = logging.DEBUG)

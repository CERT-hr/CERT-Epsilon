import unittest, psycopg2, json
from datetime import date, timedelta
from cert_epsilon.lib.db_handler import db_handler
from cert_epsilon.lib.utils import download_and_extract_zip, parse_configurations, parse_cve_per_page, parse_page_no
from werkzeug.datastructures import ImmutableMultiDict
from os import environ as env
from .utils import rm_database


class TestDatabaseHandler(unittest.TestCase):
    cursor = None
    ps_connection = None

    def setUp(self):
        rm_database()
        try:
            self.ps_connection = psycopg2.connect(
                user=env.get("POSTGRE_USER"), 
                password=env.get("POSTGRE_PASSWORD"), 
                host=env.get("POSTGRE_IP"), 
                port="",
                database=env.get("POSTGRE_DATABASE"))
            self.cursor = self.ps_connection.cursor()
        except (Exception, psycopg2.DatabaseError) as e:
            print("Error connecting to database!", e)
            return

    def tearDown(self):
        rm_database()
        if self.ps_connection:
            self.cursor.close()
            self.ps_connection.close()

    def test_get_cwe_success(self):
        '''Tests db handlers get_cwe method

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cwe', ["CWE-123", "test", "test123",])
            self.cursor.callproc('insert_cwe', ["CWE-1", "1", "a",])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        
        test_cwe1 = db_handler.get_cwe("CWE-123")
        test_cwe2 = db_handler.get_cwes("tes")
        test_cwe3 = db_handler.get_cwes("123")
        test_cwe4 = db_handler.get_cwes("CWE-123")
        self.assertEqual(test_cwe1['description'], 'test123')
        self.assertEqual(test_cwe2[0]['description'], 'test123')
        self.assertEqual(test_cwe3[0]['description'], 'test123')
        self.assertEqual(test_cwe4[0]['description'], 'test123')
        
    def test_get_cwe_fail(self):
        '''Tests db_handler's method get_cwe returns {} on non existing cwe

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_cwe = db_handler.get_cwe("Nope")
        self.assertEqual(test_cwe, {})
    
    def test_get_all_cwe(self):
        '''Tests db_handler's method get_all_cwe returns all cwes from the database

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cwe', ["CWE-1", "test", "test123",])
            self.cursor.callproc('insert_cwe', ["CWE-2", "test", "test123",])
            self.cursor.callproc('insert_cwe', ["CWE-3", "test", "test123",])
            self.cursor.callproc('insert_cwe', ["CWE-4", "test", "test123",])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        cwe_list = db_handler.get_all_cwe()
        self.assertEqual(len(cwe_list), 4)
    
    def test_insert_cwe_success(self):
        '''Tests db handler's method insert_cwe inserts cwe successfully and returns True

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_cwe = db_handler.insert_cwe("CWE-123", "test_desc","test123")
        r = None
        try:
            self.cursor.callproc('get_cwe', ["CWE-123",])
            r = self.cursor.fetchone()
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        self.assertEqual(r[1], "test_desc")
        self.assertTrue(test_cwe)

    def test_insert_existing_cwe_fail(self):
        '''Tests db handler's method insert_cwe returns False if cwe already exists
        and doesnt override existing cwe

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cwe', ["CWE-123", "test_desc", "test123",])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        test_cwe = db_handler.insert_cwe("CWE-123", "CHANGED","test123")
        self.assertFalse(test_cwe) 
        
        r = None
        # also check that insert didnt actually update data!
        try:
            self.cursor.callproc('get_cwe', ["CWE-123",])
            r = self.cursor.fetchone()
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        self.assertEqual(r[1], "test_desc")
    
    def test_get_all_cwe_for_cve(self):
        '''Tests db handler's method get_all_cwe_for_cve returns all cwe's that are connected to the cve

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cwe', ["CWE-1","test","test"])
            self.cursor.callproc('insert_cwe', ["CWE-2","test","test"])
            self.cursor.callproc('insert_cwe', ["CWE-3","test","test"])
            self.cursor.callproc('insert_cwe', ["CWE-4","test","test"])
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-1",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-2",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve_cwe', ["CVE-2020-1", "CWE-1"])
            self.cursor.callproc('insert_cve_cwe', ["CVE-2020-1", "CWE-2"])
            self.cursor.callproc('insert_cve_cwe', ["CVE-2020-1", "CWE-3"])
            self.cursor.callproc('insert_cve_cwe', ["CVE-2020-2", "CWE-4"])
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        test_cwe1 = db_handler.get_cwe_for_cve('CVE-2020-1')
        test_cwe2 = db_handler.get_cwe_for_cve('CVE-2020-2')
        self.assertEqual(len(test_cwe1), 3)
        self.assertEqual(len(test_cwe2), 1)

    def test_get_capec_success(self):
        '''Tests db handlers get_capec method, with capec that exists in the database

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        r = None
        try:
            self.cursor.callproc('insert_capec', ["CAPEC-1", "test", "test123","test456", "test789"])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass

        test_capec = db_handler.get_capec("CAPEC-1") 
        self.assertEqual(test_capec["name"], 'test')
    
    def test_get_capec_fail(self):
        '''Tests db_handler's method get_capec returns {} if requested capec doesnt exists

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_capec = db_handler.get_capec("CAPEC-1") 
        self.assertEqual(test_capec, {})  
    
    def test_insert_capec_success(self):
        '''Tests db_handler's method insert_capec returns True and inserts a new capec

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_capec = db_handler.insert_capec("CAPEC-1", "test1", "test2", "test3", "test4")
        r = None
        try:
            self.cursor.callproc('get_capec', ["CAPEC-1",])
            r = self.cursor.fetchone()[1]
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        self.assertTrue(test_capec)
        self.assertEqual(r, "test1")
    
    def test_insert_existing_capec_fail(self):
        '''Tests db_handler's method insert_capec returns False on inserting existing capec
        and doesnt override existing capec

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_capec', ["CAPEC-1", "test", "test1", "test2", "test3"])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        test = db_handler.insert_capec("CAPEC-1", "CHANGED", "test", "test", "test")
        self.assertFalse(test)
        
        r = None
        try:
            self.cursor.callproc('get_capec', ["CAPEC-1",])
            r = self.cursor.fetchone()[1]
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        self.assertEqual(r, "test")
    
    def test_get_all_capec_for_cwe(self):
        '''Tests db_handler's method get_capec_for_cwe returns all capeces for existing cwe

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_capec', ["CAPEC-1", "test", "test123", "test", "test"])
            self.cursor.callproc('insert_capec', ["CAPEC-2", "test", "test123", "test", "test"])
            self.cursor.callproc('insert_capec', ["CAPEC-3", "test", "test123", "test", "test"])
            self.cursor.callproc('insert_capec', ["CAPEC-4", "test", "test123", "test", "test"])
            self.cursor.callproc('insert_cwe', ["CWE-1", "test", "test123"])
            self.cursor.callproc('insert_cwe', ["CWE-2", "test", "test123"])
            self.cursor.callproc('insert_cwe_capec', ['CWE-1', 'CAPEC-1'])
            self.cursor.callproc('insert_cwe_capec', ['CWE-1', 'CAPEC-2'])
            self.cursor.callproc('insert_cwe_capec', ['CWE-1', 'CAPEC-3'])
            self.cursor.callproc('insert_cwe_capec', ['CWE-2', 'CAPEC-4'])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        test_1 = db_handler.get_capec_for_cwe("CWE-1")
        test_2 = db_handler.get_capec_for_cwe("CWE-2")
        self.assertEqual(len(test_1), 3)
        self.assertEqual(len(test_2), 1)

    def test_get_cve_success(self):
        '''Tests db_handler's get_cve fetches existing cve as a dictionary

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0001",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0002",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"STILL TEST",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0003",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"not a t3st",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0004",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"hidden 1test1",
                        "cvss":9
                    })
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        test_cve = db_handler.get_cve('CVE-2020-0001')
        self.assertEqual(test_cve['description'], "test")
        test_cve = db_handler.get_cves('test')
        self.assertEqual(len(test_cve), 3)

    def test_get_cve_fail(self):
        '''Tests db_handler's get_cve returns empty dictionary on non existing cve

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_cve = db_handler.get_cve('nope')
        self.assertEqual(test_cve, {})
     
    def test_insert_cve_success(self):
        '''Tests db_handler's insert_cve returns id on successfull cve insert

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_cve = db_handler.insert_cve("CVE-2020-0001","test", 9, "2020-01-01","2020-01-01")
        r = None
        try:
            self.cursor.callproc('get_cve', ["CVE-2020-0001",])
            r = self.cursor.fetchone()[1]
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        self.assertTrue(test_cve)
        self.assertEqual(r, "test")

    def test_update_cve(self):
        '''Tests db_handler's update_cve returns True on successfull cve update and False otherwise

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0001",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        test_cve1 = db_handler.update_cve("CVE-20202-0001", "new desc", 2.0,'2020-01-01','2020-01-01')
        self.assertTrue(test_cve1)

    def test_insert_existing_cve_fail(self):
        '''Tests db_handler's insert_cve returns False on trying to insert existing cve

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-1",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        test_cve = db_handler.insert_cve("CVE-2020-1", "test", 9, "2020-01-01", "2020-01-01")
        self.assertFalse(test_cve)
    
    def test_insert_operating_system_success(self):
        '''Tests db_handler's insert_operating_system returns id of successfull os insert

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        p1_id = None
        os_type = "*nix"
        try:
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        os_id = db_handler.insert_operating_system("OS1", p1_id, os_type)
        r = None
        try:
            self.cursor.callproc('get_operating_system', [os_id,])
            r = self.cursor.fetchone()
        except Exception as e:
            print(e)
       
        self.assertEqual(r[1], 'OS1')
    
    def test_insert_operating_system_fail(self):
        '''Tests db_handler's insert_operating_system returns False on trying to insert existing os

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        p1_id = None
        os_type = "windows"
        try:
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_operating_system', {'name': "OS1",'id_product': p1_id, "os_type": os_type})
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        test_os = db_handler.insert_operating_system("OS1", p1_id, os_type)
        self.assertFalse(test_os)

    def test_bulk_insert_vendors(self):
        '''Tests db_handlers bulk_insert_vendors returns n of newly inserted vendors
        
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        vendor_list = ["test1", "test2", "test3"]
        n = db_handler.bulk_insert_vendors(vendor_list)
        r = None
        try:
            self.cursor.callproc('get_all_vendors')
            r = self.cursor.fetchall()
        except Exception as e:
            pass
        for vendor in r:
            self.assertIn(vendor[1], vendor_list)
        self.assertEqual(n, 3)

    def test_bulk_insert_products(self):
        '''Tests db_handlers bulk_insert_products returns n of newly inserted products 
        
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_vendor', {'name': "vendor2"})
            v2_id = self.cursor.fetchone()[0]
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        product_list = [
                    {'name': "test1",'id_vendor': v1_id},
                    {'name': "test2",'id_vendor': v1_id},
                    {'name': "test3",'id_vendor': v2_id}
                ]
        n = db_handler.bulk_insert_products(product_list)
        r = None
        try:
            self.cursor.callproc('get_all_products')
            r = self.cursor.fetchall()
        except Exception as e:
            print(e)
            pass
        for product in r:
            self.assertIn(product[1], [p['name'] for p in product_list])
        self.assertEqual(n, 3)

    def test_get_cves_in_range(self):
        '''Tests db handler's method get_cves_in_range returns given range of cves

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-1",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-2",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-3",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-4",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        test_cves = db_handler.get_cve_in_range(0,3)
        self.assertEqual(len(test_cves), 3)

    def test_get_cve_count(self):
        '''Tests db handler's method get_cves_in_range returns given range of cves

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-1",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-2",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        test_cves = db_handler.get_cve_count()
        self.assertEqual(test_cves, 2)

    def test_get_cves_by_cvss(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass

    def test_get_cves_by_vendor(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass
    
    def test_get_cves_by_date(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass
    
    def test_get_cves_by_os(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass

    def test_get_cve_top_ten(self):
        '''Tests db_handler's get_cve_top_ten fetches cves from top 10 table 

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0001",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0002",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"STILL TEST",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0003",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"not a t3st",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-0004",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2020-01-01",
                        "description":"hidden 1test1",
                        "cvss":9
                    })
            self.cursor.execute("INSERT INTO tbl_cve_top_ten (id_cve) VALUES ('CVE-2020-0003'), ('CVE-2020-0004');")
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        test_cve = db_handler.get_cve_top_ten()
        self.assertEqual(len(test_cve), 2)
    
    def test_get_top_ten_vendor(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass
    
    def test_get_user_daily_cves(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass
    
    def test_get_user_subscriptions(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass

    def test_get_non_existing_user_subscriptions(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass
    
    def test_get_products_for_vendor(self):
        '''Tests db_handlers method get_products_for_vendor fetches all products that are from a given vendor

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_vendor', {'name': "vendor2"})
            v2_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            self.cursor.callproc('insert_product', {'name': "test2",'id_vendor': v1_id})
            self.cursor.callproc('insert_product', {'name': "test3",'id_vendor': v2_id})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        products1 = db_handler.get_products_for_vendor("vendor1")
        products2 = db_handler.get_products_for_vendor("vendor2")
        
        self.assertEqual(len(products1), 2)
        self.assertEqual(len(products2), 1)

    def test_get_product_success(self):
        '''Tests db_handler's get_product fetches existing product as a dictionary

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {"name":"test1", "id_vendor": v1_id})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        test_product = db_handler.get_product("test1")
        self.assertEqual(test_product['name'], "test1")

    def test_get_product_fail(self):
        '''Tests db_handler's get_product returns empty dictionary on non existing product

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_product = db_handler.get_product("none")
        self.assertEqual(test_product, {})
    
    def test_get_vendor_success(self):
        '''Tests db_handler's get_vendor fetches existing vendor as a dictionary

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        test_vendor = db_handler.get_vendor("vendor1")
        self.assertEqual(test_vendor['name'], "vendor1")

    def test_get_vendor_fail(self):
        '''Tests db_handler's get_vendor returns empty dictionary on non existing vendor

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_vendor = db_handler.get_vendor("none")
        self.assertEqual(test_vendor, {})
    
    def test_get_vendor_in_range(self):
        '''Tests db_handler's get_vendors_in_range fetches existing vendor as a dictionary

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            self.cursor.callproc('insert_vendor', {'name': "vendor2"})
            self.cursor.callproc('insert_vendor', {'name': "vendor3"})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        test_vendor = db_handler.get_vendors_in_range(0,2)
        self.assertEqual(len(test_vendor), 2)
        test_vendor = db_handler.get_vendors_in_range(0,1)
        self.assertEqual(len(test_vendor), 1)
    
    def test_get_vendors(self):
        '''Tests db_handler's get_vendors fetches existing vendors for a given keyword

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            self.cursor.callproc('insert_vendor', {'name': "vendor2"})
            self.cursor.callproc('insert_vendor', {'name': "vendor3"})
            self.cursor.callproc('insert_vendor', {'name': "nope"})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        test_vendor = db_handler.get_vendors("vend")
        self.assertEqual(len(test_vendor), 3)

    def test_get_vendor_count(self):
        '''Tests db_handler's get_vendor_count fetches total number of vendors in the database

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "vendor1"})
            self.cursor.callproc('insert_vendor', {'name': "vendor2"})
            self.cursor.callproc('insert_vendor', {'name': "vendor3"})
            self.ps_connection.commit()
        except Exception as e:
            print(e)
        
        test_vendor = db_handler.get_vendor_count()
        self.assertEqual(test_vendor, 3)
    
    def test_get_vendor_cves(self):
        '''Tests db_handler's get_vendor_cves method returns number of cves for given vendor
        
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:            
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-1",
                        "published_date":"2020-01-01",
                        "last_modified_date":str(date.today()-timedelta(days=1))+' 01:00:00',
                        "description":"test",
                        "cvss":1
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-2",
                        "published_date":"2020-01-01",
                        "last_modified_date":str(date.today()-timedelta(days=1))+' 01:00:00',
                        "description":"test",
                        "cvss":1
                    })
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-3",
                        "published_date":"2020-01-01",
                        "last_modified_date":str(date.today()-timedelta(days=1))+' 01:00:00',
                        "description":"test",
                        "cvss":2
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-4",
                        "published_date":"2020-01-01",
                        "last_modified_date":str(date.today()-timedelta(days=1))+' 01:00:00',
                        "description":"test",
                        "cvss":2
                    })
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-5",
                        "published_date":"2020-01-01",
                        "last_modified_date":str(date.today()-timedelta(days=1))+' 01:00:00',
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-6",
                        "published_date":"2020-01-01",
                        "last_modified_date":"2019-01-01",
                        "description":"test",
                        "cvss":10
                    })
                    
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test2",'id_vendor': v1_id})
            p2_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_operating_system', {'name': "OS1",'id_product': p1_id, 'os_type':'test'})
            self.cursor.callproc('insert_operating_system', {'name': "OS2",'id_product': p2_id, 'os_type':'test'})
            self.cursor.callproc('insert_cve_product', ["CVE-2020-1", p1_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-2", p1_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-3", p2_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-4", p2_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-5", p2_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-6", p2_id])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            
        test1 = db_handler.get_vendor_cves("test1")
        test2 = db_handler.get_vendor_cves("test1", True)
        
        self.assertEqual(test1,6)
        #self.assertEqual(test2,5)

    def test_get_operating_system_types(self):
        '''Tests db_handler's method get_operating_system_types returns dinstinct operating system types from the database

        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''

        try:
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.ps_connection.commit()
            self.cursor.callproc('insert_vendor', {'name': "test2"})
            v2_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test2",'id_vendor': v2_id})
            p2_id = self.cursor.fetchone()[0]
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        try:
            self.cursor.callproc('insert_operating_system', ["OS1", p1_id, "*nix", ])
            self.cursor.callproc('insert_operating_system', ["OS2", p2_id, "*nix", ])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        os_type_list = db_handler.get_operating_system_types()
        self.assertEqual(len(os_type_list), 1)

    def test_filter(self):
        '''Tests db_handler's filter_cves method applys filters given immutable dictionary of arguments

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-1",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2020-01-01",
                        "description":"test",
                        "cvss":1
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-2",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2020-01-01",
                        "description":"test",
                        "cvss":1
                    })
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-3",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2020-01-05",
                        "description":"test",
                        "cvss":2
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-4",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2020-01-06",
                        "description":"test",
                        "cvss":2
                    })
            self.cursor.callproc('insert_cve', {
                        "cve_id":"CVE-2020-5",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2020-01-07",
                        "description":"test",
                        "cvss":9
                    })
            self.cursor.callproc('insert_cve',
                    {
                        "cve_id":"CVE-2020-6",
                        "last_modified_date":"2020-01-01",
                        "published_date":"2019-01-01",
                        "description":"test",
                        "cvss":10
                    })
                    
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test2",'id_vendor': v1_id})
            p2_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_operating_system', {'name': "OS1",'id_product': p1_id, 'os_type':'test'})
            self.cursor.callproc('insert_operating_system', {'name': "OS2",'id_product': p2_id, 'os_type':'test'})
            self.cursor.callproc('insert_cve_product', ["CVE-2020-1", p1_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-2", p1_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-3", p2_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-4", p2_id])
            self.cursor.callproc('insert_cve_product', ["CVE-2020-5", p2_id])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            
        # FILTER BY CVSS
        test_cvss1 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'more_than'),('cvss', 9)]))
        test_cvss2 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'more_than'),('cvss', 1)]))
        test_cvss3 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'less_than'),('cvss', 2)]))
        test_cvss4 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'less_than'),('cvss', 9)]))
        test_cvss5 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'equal'),('cvss', 9)]))
        test_cvss6 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'more_than'),('cvss', 'invalid')]))
        test_cvss7 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'less_than'),('cvss', 'invalid')]))
        test_cvss8 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'equal'),('cvss', 'invalid')]))
        test_cvss9 = db_handler.filter_cves(ImmutableMultiDict([('cvss_mode', 'invalid')]))
        self.assertEqual(len(test_cvss1), 1)
        self.assertEqual(len(test_cvss2), 4)
        self.assertEqual(len(test_cvss3), 2)
        self.assertEqual(len(test_cvss4), 4)
        self.assertEqual(len(test_cvss5), 1)
        self.assertEqual(len(test_cvss6), 0)
        self.assertEqual(len(test_cvss7), 0)
        self.assertEqual(len(test_cvss8), 0)
        self.assertEqual(len(test_cvss9), 0)
        # =============== 
        # FILTER BY DATE
        test_date1 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'until'),('date_end', '2020-01-05')]))
        test_date2 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'between'),('date_start', '2019-01-01'),('date_end', '2020-01-01')]))
        test_date3 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'from'),('date_start', '2020-01-05')]))
        test_date4 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'invalid')]))
        test_date5 = db_handler.filter_cves(ImmutableMultiDict([('date_start', 'invalid')]))
        test_date6 = db_handler.filter_cves(ImmutableMultiDict([('date_end', 'invalid')]))
        test_date7 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'until'),('date_end', 'invalid')]))
        test_date8 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'from'),('date_start', 'invalid')]))
        test_date9 = db_handler.filter_cves(ImmutableMultiDict([('date_mode', 'until'),('date_end', '2010-01-01')]))
        self.assertEqual(len(test_date1), 4)
        self.assertEqual(len(test_date2), 3)
        self.assertEqual(len(test_date3), 3)
        self.assertEqual(len(test_date4), 0)
        self.assertEqual(len(test_date5), 0)
        self.assertEqual(len(test_date6), 0)
        self.assertEqual(len(test_date7), 0)
        self.assertEqual(len(test_date8), 0)
        self.assertEqual(len(test_date9), 0)
        # =============== 
        # FILTER BY OS
        test_os1 = db_handler.filter_cves(ImmutableMultiDict([('os', 'OS1')]))
        test_os2 = db_handler.filter_cves(ImmutableMultiDict([('os', 'OS1'),('os', 'OS2')]))
        test_os3 = db_handler.filter_cves(ImmutableMultiDict([('os', 'invalid')]))
        self.assertEqual(len(test_os1), 2)
        self.assertEqual(len(test_os2), 5)
        self.assertEqual(len(test_os3), 0)
        # =============== 
        # FILTER BY VENDOR
        test_vendor1 = db_handler.filter_cves(ImmutableMultiDict([('vendor', 'test1')]))
        test_vendor2 = db_handler.filter_cves(ImmutableMultiDict([('vendor', 'invalid')]))
        self.assertEqual(len(test_vendor1), 5)
        self.assertEqual(len(test_vendor2), 0)
        # =============== 
        # COMBINATIONS
        test_cvss_and_date1 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'until'),('date_end', '2020-01-05'), 
                ('cvss_mode', 'equal'), ('cvss', 2)
            ]))  
        test_cvss_and_date2 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1)
            ]))  
        test_cvss_and_date3 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'invalid'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1)
            ]))  
        test_cvss_and_date4 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', 'invalid'), 
                ('cvss_mode', 'more_than'), ('cvss', 1)
            ]))  
        test_cvss_and_date5 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'invalid'), ('cvss', 1)
            ]))  
        test_cvss_and_date6 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 'invalid')
            ]))  
        self.assertEqual(len(test_cvss_and_date1), 1)
        self.assertEqual(len(test_cvss_and_date2), 2)
        self.assertEqual(len(test_cvss_and_date3), 0)
        self.assertEqual(len(test_cvss_and_date4), 0)
        self.assertEqual(len(test_cvss_and_date5), 0)
        self.assertEqual(len(test_cvss_and_date6), 0)
        test_cvss_date_and_os1 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'until'),('date_end', '2020-01-05'), 
                ('cvss_mode', 'equal'), ('cvss', 2),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os2 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os3 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'invalid'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os4 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', 'invalid'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os5 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'invalid'), ('cvss', 1),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os6 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 'invalid'),
                ('os', 'OS2')
            ]))  
        test_cvss_date_and_os7 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'invalid')
            ]))  
        self.assertEqual(len(test_cvss_date_and_os1), 1)
        self.assertEqual(len(test_cvss_date_and_os2), 2)
        self.assertEqual(len(test_cvss_date_and_os3), 0)
        self.assertEqual(len(test_cvss_date_and_os4), 0)
        self.assertEqual(len(test_cvss_date_and_os5), 0)
        self.assertEqual(len(test_cvss_date_and_os6), 0)
        self.assertEqual(len(test_cvss_date_and_os7), 0)
        
     
        test_cvss_date_os_and_vendor1 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'until'),('date_end', '2020-01-05'), 
                ('cvss_mode', 'equal'), ('cvss', 2),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor2 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-01'), 
                ('cvss_mode', 'more_than'), ('cvss', 0),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor3 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'invalid'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor4 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', 'invalid'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor5 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'invalid'), ('cvss', 1),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor6 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 'invalid'),
                ('os', 'OS2'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor7 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'invalid'),
                ('vendor', 'test1')
            ]))  
        test_cvss_date_os_and_vendor8 = db_handler.filter_cves(ImmutableMultiDict([
                ('date_mode', 'from'),('date_start', '2020-01-06'), 
                ('cvss_mode', 'more_than'), ('cvss', 1),
                ('os', 'OS2'),
                ('vendor', 'invalid')
            ]))  
        
        self.assertEqual(len(test_cvss_date_os_and_vendor1), 1)
        self.assertEqual(len(test_cvss_date_os_and_vendor2), 3)
        self.assertEqual(len(test_cvss_date_os_and_vendor3), 0)
        self.assertEqual(len(test_cvss_date_os_and_vendor4), 0)
        self.assertEqual(len(test_cvss_date_os_and_vendor5), 0)
        self.assertEqual(len(test_cvss_date_os_and_vendor6), 0)
        self.assertEqual(len(test_cvss_date_os_and_vendor7), 0)
        self.assertEqual(len(test_cvss_date_os_and_vendor8), 0)
        # =============== 
    
    def test_get_operation_system_by_type(self):
        '''Tests db_handler's method get_operation_system_by_type returns dinstinct operating system form selected type from the database

        :Author: Renato Kaćera <rkacera@carnet.hr>
        '''
        try:
            self.cursor.callproc('insert_vendor', {'name': "test1"})
            v1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test1",'id_vendor': v1_id})
            p1_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_vendor', {'name': "test2"})
            v2_id = self.cursor.fetchone()[0]
            self.cursor.callproc('insert_product', {'name': "test2",'id_vendor': v2_id})
            p2_id = self.cursor.fetchone()[0]
            self.ps_connection.commit()
        except Exception as e:
            print(e)

        try:
            self.cursor.callproc('insert_operating_system', ["OS1", p1_id, "*nix", ])
            self.cursor.callproc('insert_operating_system', ["OS1", p2_id, "*nix", ])
            self.ps_connection.commit()
        except Exception as e:
            print(e)
            pass
        os_type_list = db_handler.get_operation_system_by_type("*nix")
        self.assertEqual(len(os_type_list), 1)

class TestUtilities(unittest.TestCase):

    def test_download_and_extract_zip(self):
        '''
        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        pass

    def test_parse_configuration(self):
        '''Tests parse_configurations parses dictionary and returns list of dictionaries 

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        test_dictionary = json.loads("""
                    [{
                        "operator" : "AND",
                        "children" : [ {
                            "operator" : "OR",
                            "cpe_match" : [ {
                                    "vulnerable" : true,
                                    "cpe23Uri" : "cpe:2.3:o:test_vendor1:test_product1:1.1:*:*:*:*:*:*:*"
                                } ]
                            }, {
                            "operator" : "OR",
                            "cpe_match" : [ {
                                    "vulnerable" : true,
                                    "cpe23Uri" : "cpe:2.3:a:test_vendor2:test_product2:2.2:*:*:*:*:*:*:*"
                                }, {
                                    "vulnerable" : true,
                                    "cpe23Uri" : "cpe:2.3:a:test_vendor2:test_product3:2.3:*:*:*:*:*:*:*"
                                } ]
                            }]
                    }, {
                        "operator" : "OR",
                        "cpe_match" : [ {
                                "vulnerable" : true,
                                "cpe23Uri" : "cpe:2.3:o:test_vendor3:test_product4:3.1:*:*:*:*:*:*:*"
                            }, {
                                "vulnerable" : true,
                                "cpe23Uri" : "cpe:2.3:o:test_vendor3:test_product5:3.2:*:*:*:*:*:*:*"
                            }, {
                                "vulnerable" : false,
                                "cpe23Uri" : "cpe:2.3:o:test_vendor3:test_product6:3.3p:*:*:*:*:*:*:*"
                            }]
                    }]
                """)
        parsed_list = parse_configurations(test_dictionary)
        self.assertEqual(len(parsed_list), 5)
        for i in range(1,6):
            self.assertIn("test_product"+str(i), [x["product"] for x in parsed_list])
        for i in range(1,4):
            self.assertIn("test_vendor"+str(i), [x["vendor"] for x in parsed_list])

        for item in parsed_list:
            if "test_product1" in item:
                self.assertEqual(item["version"], "1.1")
            elif "test_product2" in item:
                self.assertEqual(item["version"], "2.2")
            elif "test_product3" in item:
                self.assertEqual(item["version"], "2.3")
            elif "test_product4" in item:
                self.assertEqual(item["version"], "3.1")
            elif "test_product5" in item:
                self.assertEqual(item["version"], "3.2")

    def test_parse_cve_per_page(self):
        '''Tests parse_configurations parses dictionary and returns list of dictionaries 

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        self.assertEqual(parse_cve_per_page(25), 25)
        self.assertEqual(parse_cve_per_page(50), 50)
        self.assertEqual(parse_cve_per_page(100), 100)
        self.assertEqual(parse_cve_per_page(110), 100)
        self.assertEqual(parse_cve_per_page(38), 50)
        self.assertEqual(parse_cve_per_page(37), 25)
        self.assertEqual(parse_cve_per_page(0), 25)
        self.assertEqual(parse_cve_per_page(76), 100)
        self.assertEqual(parse_cve_per_page("a"), 25)

    def test_parse_page_no(self):
        '''Tests parse_page_no parses int and returns integer

        :Author: Karlo Kegljevic <kkegljev@carnet.hr>
        '''
        self.assertEqual(parse_page_no(1), 1)
        self.assertEqual(parse_page_no(100), 100)
        self.assertEqual(parse_page_no("a"), 0)



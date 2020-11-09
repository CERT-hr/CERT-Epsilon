import os, tempfile, pytest, re
from cert_epsilon import app
from .utils import rm_database
from cert_epsilon.lib.db_handler import db_handler

@pytest.fixture
def client():
    rm_database()
    with app.app.test_client() as client:
        yield client
    rm_database()


def test_empty_home_page(client):
    rv = client.get('/')
    assert b'Trenutno nema zapisa o CVE-ovima' in rv.data

def test_home_page(client):
    try:
        db_handler.insert_cve("CVE-2020-0001", "test", 9, "2020-01-01","2020-01-01")
    except Exception as e:
        print(e)
    rv = client.get('/')
    assert b'Trenutno nema zapisa o CVE-ovima' not in rv.data
    assert b'CVE-2020-0001' in rv.data

# def test_home_filter(client):
#     db_handler.insert_cve("CVE-2020-1", "test", 1, "2020-01-01","2020-01-01")
#     db_handler.insert_cve("CVE-2020-2", "test", 1, "2020-01-01","2020-01-01")
#     db_handler.insert_cve("CVE-2020-3", "test", 2, "2020-01-01","2020-01-05")
#     db_handler.insert_cve("CVE-2020-4", "test", 2, "2020-01-01","2020-01-06")
#     db_handler.insert_cve("CVE-2020-5", "test", 9, "2020-01-01","2020-01-07")
#     db_handler.insert_cve("CVE-2020-6", "test", 10, "2020-01-01","2019-01-01")

#     v1_id = db_handler.insert_vendor('test1')
#     p1_id = db_handler.insert_product('test1', v1_id)
#     p2_id = db_handler.insert_product('test2', v1_id)
#     db_handler.insert_operating_system('OS1', p1_id, 'test')
#     db_handler.insert_operating_system('OS2', p2_id, 'test')
#     db_handler.insert_xref_cve_product("CVE-2020-1", p1_id)
#     db_handler.insert_xref_cve_product("CVE-2020-2", p1_id)
#     db_handler.insert_xref_cve_product("CVE-2020-3", p2_id)
#     db_handler.insert_xref_cve_product("CVE-2020-4", p2_id)
#     db_handler.insert_xref_cve_product("CVE-2020-5", p2_id)

        

#     cve_search_string = "entry entry-id"
#     # FILTER BY CVSS
#     test_cvss1 = client.get('/?cvss_mode=more_than&cvss=9')
#     test_cvss2 = client.get('/?cvss_mode=more_than&cvss=1')
#     test_cvss3 = client.get('/?cvss_mode=less_than&cvss=2')
#     test_cvss4 = client.get('/?cvss_mode=less_than&cvss=9')
#     test_cvss5 = client.get('/?cvss_mode=equal&cvss=9')
#     test_cvss6 = client.get('/?cvss_mode=more_than&cvss=invalid')
#     test_cvss7 = client.get('/?cvss_mode=less_than&cvss=invalid')
#     test_cvss8 = client.get('/?cvss_mode=equal&cvss=invalid')
#     test_cvss9 = client.get('/?cvss_mode=invalid')
#     assert len(test_cvss1.decode().find(cve_search_string)) == 1
#     assert len(test_cvss2) == 4
#     assert len(test_cvss3) == 2
#     assert len(test_cvss4) == 4
#     assert len(test_cvss5) == 1
#     assert len(test_cvss6) == 0
#     assert len(test_cvss7) == 0
#     assert len(test_cvss8) == 0
#     assert len(test_cvss9) == 0
#     # =============== 
#     # FILTER BY DATE
#     test_date1 = client.get('/?date_mode=until&date_end=2020-01-05')
#     test_date2 = client.get('/?date_mode=between&date_start=2019-01-01&date_end=2020-01-01')
#     test_date3 = client.get('/?date_mode=from&date_start=2020-01-05')
#     test_date4 = client.get('/?date_mode=invalid')
#     test_date5 = client.get('/?date_start=invalid')
#     test_date6 = client.get('/?date_end=invalid')
#     test_date7 = client.get('/?date_mode=until&date_end=invalid')
#     test_date8 = client.get('/?date_mode=from&date_start=invalid')
#     test_date9 = client.get('/?date_mode=until&date_end=2010-01-01')
#     assert len(test_date1), 4)
#     assert len(test_date2), 3)
#     assert len(test_date3), 3)
#     assert len(test_date4), 0)
#     assert len(test_date5), 0)
#     assert len(test_date6), 0)
#     assert len(test_date7), 0)
#     assert len(test_date8), 0)
#     assert len(test_date9), 0)
#     # =============== 
#     # FILTER BY OS
#     test_os1 = client.get('/?os=OS1')
#     test_os2 = client.get('/?os=OS1&os=OS2')
#     test_os3 = client.get('/?os=invalid')
#     assert len(test_os1), 2)
#     assert len(test_os2), 5)
#     assert len(test_os3), 0)
#     # =============== 
#     # FILTER BY VENDOR
#     test_vendor1 = client.get('/?vendor=test1')
#     test_vendor2 = client.get('/?vendor=invalid')
#     assert len(test_vendor1), 5)
#     assert len(test_vendor2), 0)
    # =============== 
    # COMBINATIONS
    # test_cvss_and_date1 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=until&date_end=2020-01-05'), 
    #         ('cvss_mode=equal'), ('cvss=2'
    #     )  
    # test_cvss_and_date2 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1'
    #     )  
    # test_cvss_and_date3 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=invalid&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1'
    #     )  
    # test_cvss_and_date4 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=invalid'), 
    #         ('cvss_mode=more_than'), ('cvss=1'
    #     )  
    # test_cvss_and_date5 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=invalid'), ('cvss=1'
    #     )  
    # test_cvss_and_date6 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=invalid')
    #     )  
    # assert len(test_cvss_and_date1), 1)
    # assert len(test_cvss_and_date2), 2)
    # assert len(test_cvss_and_date3), 0)
    # assert len(test_cvss_and_date4), 0)
    # assert len(test_cvss_and_date5), 0)
    # assert len(test_cvss_and_date6), 0)
    # test_cvss_date_and_os1 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=until&date_end=2020-01-05'), 
    #         ('cvss_mode=equal'), ('cvss=2',
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os2 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os3 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=invalid&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os4 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=invalid'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os5 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=invalid'), ('cvss=1',
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os6 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=invalid'),
    #         ('os=OS2')
    #     )  
    # test_cvss_date_and_os7 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=invalid')
    #     )  
    # assert len(test_cvss_date_and_os1), 1)
    # assert len(test_cvss_date_and_os2), 2)
    # assert len(test_cvss_date_and_os3), 0)
    # assert len(test_cvss_date_and_os4), 0)
    # assert len(test_cvss_date_and_os5), 0)
    # assert len(test_cvss_date_and_os6), 0)  
    # assert len(test_cvss_date_and_os7), 0)
    
 
    # test_cvss_date_os_and_vendor1 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=until&date_end=2020-01-05'), 
    #         ('cvss_mode=equal'), ('cvss=2',
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor2 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-01'), 
    #         ('cvss_mode=more_than'), ('cvss=0',
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor3 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=invalid&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor4 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=invalid'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor5 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=invalid'), ('cvss=1',
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor6 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=invalid'),
    #         ('os=OS2'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor7 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=invalid'),
    #         ('vendor=test1')
    #     )  
    # test_cvss_date_os_and_vendor8 = db_handler.filter_cves(ImmutableMultiDict([
    #         ('date_mode=from&date_start=2020-01-06'), 
    #         ('cvss_mode=more_than'), ('cvss=1',
    #         ('os=OS2'),
    #         ('vendor=invalid')
    #     )  
    
    # assert len(test_cvss_date_os_and_vendor1), 1)
    # assert len(test_cvss_date_os_and_vendor2), 3)
    # assert len(test_cvss_date_os_and_vendor3), 0)
    # assert len(test_cvss_date_os_and_vendor4), 0)
    # assert len(test_cvss_date_os_and_vendor5), 0)
    # assert len(test_cvss_date_os_and_vendor6), 0)
    # assert len(test_cvss_date_os_and_vendor7), 0)
    # assert len(test_cvss_date_os_and_vendor8), 0)

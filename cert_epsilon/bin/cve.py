import sys, zipfile, os, shutil, json, traceback, logging

sys.path.append("../")

from lib.utils import download_and_extract_zip, parse_configurations
from lib.db_handler import db_handler

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
BASE_URL = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-"
EXTENSION = ".json.zip"
BASE_NAME = "nvdcve-1.1-"
OPERATING_SYSTEMS = None
with open("./operating_systems.json") as f:
    OPERATING_SYSTEMS = json.load(f)

def main():
    global OPERATING_SYSTEMS
    duplicates = set()
    inserted_vendors = set()
    for year in range(2002,2021):
        print("Parsing year %s"% (year,))
        download_and_extract_zip(BASE_URL+str(year)+EXTENSION, DIR_PATH, BASE_NAME+str(year))
        JSON_NAME = BASE_NAME + str(year) + ".json"
        JSON_PATH = os.path.join(DIR_PATH, BASE_NAME+str(year), JSON_NAME)
        c = 0
        cves = []
        with open(JSON_PATH, 'r') as f:
            cves = json.load(f)
        if len(cves) < 1:
            print("File at path %s is empty!" % (JSON_PATH,))
            sys.exit(1)
        print_exception = False
        for count, cve in enumerate(cves['CVE_Items']):
            try:
                cve_id = cve['cve']['CVE_data_meta']['ID']
                description = cve['cve']['description']['description_data'][0]['value']
                if "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER." in description:
                    continue
                published_date = cve['publishedDate'].split("T")
                published_date = str(published_date[0]) + ' ' + str(''.join(published_date[1][:-1]))
                last_modified_date = cve['lastModifiedDate'].split("T")
                last_modified_date = str(last_modified_date[0]) + ' ' + str(''.join(last_modified_date[1][:-1]))
                cwes = [x['value'] for x in cve['cve']['problemtype']['problemtype_data'][0]['description']]
                tmp=cve['cve']['references']['reference_data']
                if len(tmp) > 0:
                    reference_links= '|'.join([x['url'] for x in tmp])
                else:
                    reference_links=None
                cvss = 0 
                exploitability_score=None
                impact_score=None
                severity=None
                cvss_access_vector=None
                cvss_vector_string=None
                cvss_access_complexity=None
                cvss_authentication=None
                cvss_confidentiality_impact=None
                cvss_integrity_impact=None
                cvss_availability_impact=None
                tmp=cve['impact']
                if "baseMetricV2" in tmp:
                    cvss = tmp['baseMetricV2']['cvssV2']['baseScore']
                    tmp = tmp["baseMetricV2"]
                    exploitability_score=tmp['exploitabilityScore']
                    impact_score=tmp['impactScore']
                    severity=tmp['severity']
                    cvss_access_vector=tmp['cvssV2']['accessVector']
                    cvss_vector_string=tmp['cvssV2']['vectorString']
                    cvss_access_complexity=tmp['cvssV2']['accessComplexity']
                    cvss_authentication=tmp['cvssV2']['authentication']
                    cvss_confidentiality_impact=tmp['cvssV2']['confidentialityImpact']
                    cvss_integrity_impact=tmp['cvssV2']['integrityImpact']
                    cvss_availability_impact=tmp['cvssV2']['availabilityImpact']
                elif "baseMetricV3" in tmp:
                    cvss = tmp['baseMetricV3']['cvssV3']['baseScore']
                    tmp = tmp["baseMetricV3"]
                    exploitability_score=tmp['exploitabilityScore']
                    impact_score=tmp['impactScore']
                    severity=tmp['cvssV3']['baseSeverity']
                    cvss_access_vector=tmp['cvssV3']['attackVector']
                    cvss_vector_string=tmp['cvssV3']['vectorString']
                    cvss_access_complexity=tmp['cvssV3']['attackComplexity']
                    cvss_authentication="-"
                    cvss_confidentiality_impact=tmp['cvssV3']['confidentialityImpact']
                    cvss_integrity_impact=tmp['cvssV3']['integrityImpact']
                    cvss_availability_impact=tmp['cvssV3']['availabilityImpact']
                
                db_handler.insert_cve(
                            cve_id,
                            description,
                            cvss,
                            published_date,
                            last_modified_date,
                            reference_links,
                            exploitability_score,
                            impact_score,
                            severity,
                            cvss_access_vector,
                            cvss_vector_string,
                            cvss_access_complexity,
                            cvss_authentication,
                            cvss_confidentiality_impact,
                            cvss_integrity_impact,
                            cvss_availability_impact
                        )
                for cwe in cwes:
                    db_handler.insert_xref_cve_cwe(cve_id, cwe)
                c+=1
                

                parsed_config = parse_configurations(cve['configurations']['nodes'])
                if len(parsed_config) == 0:
                    continue
             
                for config in parsed_config:
                    if (config['vendor'],config['product']) in duplicates:
                        p_id = db_handler.get_product(config['product'])['product_id']
                        if p_id:
                            db_handler.insert_xref_cve_product(cve_id, db_handler.get_product(config['product'])['product_id'])
                        continue
                    else:
                        duplicates.add((config['vendor'],config['product']))
                    
                    vendor_id = None
                    product_id = None
                    # ===============================
                    # Here insert version of the 
                    # product later on in development
                    if config['vendor'] not in inserted_vendors:
                        inserted_vendors.add(config['vendor'])
                        vendor_id = db_handler.insert_vendor(str(config["vendor"]))
                        product_id = db_handler.insert_product(str(config["product"]), vendor_id)
                    else:
                        vendor_id = db_handler.get_vendor(str(config['vendor']))['vendor_id']
                        product_id = db_handler.insert_product(str(config['product']), vendor_id)
                        
                    db_handler.insert_xref_cve_product(cve_id, product_id)
                    for n, operating_system in enumerate(OPERATING_SYSTEMS):
                        if config['product'] in operating_system['product_name'] and config['vendor'] in operating_system['vendor_name']:
                            db_handler.insert_operating_system(operating_system['name'], product_id, operating_system["os_type"])
                            OPERATING_SYSTEMS[n]["product_name"].remove(config['product'])
                            break
            except Exception:
                logging.warning(traceback.print_exc())
                continue
            print("Status[CVE]: %s/%s           " % (count+1,len(cves['CVE_Items'])), end="\r") 
        print()
        print("Successfully inserted %s CVE-s for year %s" % (c, year))
        if c != len(cves):
            print("Didn't insert %s cves cause of missformated data" % (len(cves['CVE_Items'])-c,))
        
        print("Removing files for year %s.." % (year,))
        shutil.rmtree(os.path.join(DIR_PATH, BASE_NAME + str(year)))
        os.remove(os.path.join(DIR_PATH, BASE_NAME + str(year) + ".zip"))
        print("Removed")
        print("="*10)

if __name__ == '__main__':
    main()
else:
    print("cve.py is used as a standalone executable!")
    sys.exit(1)


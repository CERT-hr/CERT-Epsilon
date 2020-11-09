import sys, zipfile, os, shutil
from defusedxml.ElementTree import parse

sys.path.append("../")

from lib.utils import download_and_extract_zip
from lib.db_handler import db_handler

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
URL = "https://cwe.mitre.org/data/xml/cwec_v4.1.xml.zip"
BASE_NAME = "cwec_v4.1"
XML_NAME = BASE_NAME + ".xml"

def main():
    print("Starting CWE parser...")
    download_and_extract_zip(URL, DIR_PATH, BASE_NAME)
    et = parse(os.path.join(DIR_PATH, BASE_NAME, XML_NAME))
    root = et.getroot()
    for count, cwe in enumerate(root[0]):
        try:
            ID = "CWE-"+cwe.attrib['ID']
            NAME = cwe.attrib['Name']
            DESCRIPTION = cwe.find('{http://cwe.mitre.org/cwe-6}Description').text
        except Exception:
            print("This cwe: [%s] doesnt have id or name, im skipping." % (cwe,))
            continue
        db_handler.insert_cwe(ID,NAME,DESCRIPTION)
        print("Status[CWE]: %s/%s           " % (count+1,len(root[0])), end="\r") 
    db_handler.insert_cwe("NVD-CWE-Other", "NVD-CWE-Other", "NVD's other CWE")
    db_handler.insert_cwe("NVD-CWE-noinfo", "NVD-CWE-noinfo", "NVD's no info CWE")
    print("Successfully inserted %s CWE-s" % (len(root[0],)))
    print("Removing files..")
    shutil.rmtree(os.path.join(DIR_PATH, BASE_NAME))
    os.remove(os.path.join(DIR_PATH, BASE_NAME+".zip"))
    print("Removed")

if __name__ == '__main__':
    main()
else:
    print("cwe.py is used as a standalone executable!")
    sys.exit(1)

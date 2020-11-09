import zipfile, os, shutil, sys, glob
from defusedxml.ElementTree import parse

sys.path.append("../")

from lib.utils import download_and_extract_zip
from lib.db_handler import db_handler

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
URL = "https://capec.mitre.org/data/xml/views/1000.xml.zip"
BASE_NAME = "capec1"
XML_NAME = "1000.xml"

def main():
    print("Starting CAPEC parser...")
    download_and_extract_zip(URL, DIR_PATH, BASE_NAME)
    et = parse(os.path.join(DIR_PATH, BASE_NAME, XML_NAME))    
    root = et.getroot()
    for count, capec in enumerate(root[0]):
        try:
            ID = "CAPEC-"+capec.attrib['ID']
            NAME = capec.attrib['Name']
            DESCRIPTION = ""
            description = capec.find("{http://capec.mitre.org/capec-3}Description")
            if len(description):
                DESCRIPTION = " ".join([x.text for x in description])
            else:
                DESCRIPTION = description.text
        except Exception:
            print("This capec: [%s] doesnt have id, name or description, im skipping." % (capec,))
            continue

        PREREQ = None 
        try:
            PREREQ = "|".join(
                    [x.text for x in capec.find("{http://capec.mitre.org/capec-3}Prerequisites")]
                )
        except Exception:
            print("%s doesnt have the prerequisites, assigning 'no'" % (ID,))
            PREREQ = "no"

        MITIGATIONS = None
        try:
            mitigations_element = capec.find("{http://capec.mitre.org/capec-3}Mitigations")
        except Exception:
            print("%s doesnt have the mitigations, assigning 'no'" % (ID,))
            MITIGATIONS = "no"
        
        if mitigations_element is None: # if mitigation is none, i wont parse it, and i will just insert it as is
            db_handler.insert_capec(ID,NAME,DESCRIPTION,PREREQ,"no")
        else:
            MITIGATIONS = []
            for mitigation in mitigations_element:
                if len(mitigation):
                    MITIGATIONS.append(" ".join([x.text for x in mitigation]))
                else:
                    MITIGATIONS.append(mitigation.text)
            MITIGATIONS = filter(None, MITIGATIONS) # remove None from list, can happen cause nice formating mitre..
            MITIGATIONS = "|".join(MITIGATIONS)
            db_handler.insert_capec(ID,NAME,DESCRIPTION,PREREQ,MITIGATIONS)

        cwes = capec.find("{http://capec.mitre.org/capec-3}Related_Weaknesses")
        if cwes:
            for cwe in cwes:
                try:
                    db_handler.insert_xref_cwe_capec("CWE-"+cwe.attrib["CWE_ID"], ID)
                except Exception:
                    pass
        print("Status[CAPEC]: %s/%s           " % (count+1,len(root[0])), end="\r") 
    
    print("Successfully inserted %s CAPEC-es" % (len(root[0],)))
    print("Removing data...")
    print(BASE_NAME, end="")
    shutil.rmtree(os.path.join(DIR_PATH, BASE_NAME))
    print(" [x]")
    print("Removing zip files..")
    os.remove(os.path.join(DIR_PATH, BASE_NAME+".zip"))
    print("Done")

if __name__ == '__main__':
    main()
else:
    print("capec.py is used as a standalone executable!")
    sys.exit(1)

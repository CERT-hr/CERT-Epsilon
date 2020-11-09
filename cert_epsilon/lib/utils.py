import requests, sys, zipfile, os, re
from itertools import chain
import uuid
from itsdangerous import URLSafeTimedSerializer
from os import environ as env
from dotenv import load_dotenv
from email.mime.text import MIMEText
import smtplib
import jinja2


def download_and_extract_zip(url, dir_path, filename):
    '''Downloads and extracts a zip file from a given url

    :param url: url to zip to download
    :param dir_path: path in which you want your zip saved
    :param filename: filename of decompressed file/folder
    
    :Author: Karlo Kegljevic <kkegljev@carnet.hr>
    '''
    
    print("Downloading from %s..." % (url,))
    zipname = filename + ".zip"
    r = requests.get(url, stream=True)
    with open(os.path.join(dir_path, zipname), 'wb') as fd:
        length = r.headers.get('content-length')
        if length is None:
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
        else:
            dl = 0
            length = int(length)
            for chunk in r.iter_content(chunk_size=128):
                fd.write(chunk)
                dl+=len(chunk)
                done = int(50*dl/length)
                sys.stdout.write("\r[%s%s]" % ('X'*done, '-'*(50-done)))
                sys.stdout.flush()
            print()
    if not os.path.exists(os.path.join(dir_path, zipname)):
        print("Problems with downloading file!")
        sys.exit(1)
    else:
        print("Successfully downloaded file")

    with zipfile.ZipFile(os.path.join(dir_path, zipname), 'r') as zf:
        zf.extractall(os.path.join(dir_path, filename))
    
    
    if not os.path.exists(os.path.join(dir_path, filename)):
        print("Problems with unzipping file!")
        sys.exit(1)
    else:
        print("Extracted zip on path=> %s" % (dir_path,))


def parse_configurations(nodes):
    '''Parses configurations from nvdcve source

    :param nodes: configuration nodes from single cve item in nvdcve1.1 json source
    :rtype: dict 
    :return List of dictionaries containing vendors, products and versions of products
    :Author: Karlo Kegljevic <kkegljev@carnet.hr>
    '''
    def find_cpes(dictionary):
        for k, v in dictionary.items():
            if k == "cpe_match":
                yield v
            elif isinstance(v, dict):
                for result in find_cpes(v):
                    yield result
            elif isinstance(v, list):
                for d in v:
                    for result in find_cpes(d):
                        yield result

    all_cpes = []
    for node in nodes:
        all_cpes.extend(chain.from_iterable(find_cpes(node)))

    ret = []
    for cpe in all_cpes:
        if not cpe["vulnerable"]:
            continue
        try:
            spl = cpe["cpe23Uri"].split(':')
            ret.append({"vendor":spl[3], "product":spl[4], "version":str(spl[5])})
        except Exception as e:
            print(e)
            continue
    return ret

def parse_cve_per_page(cve_per_page):
    '''Parses cves per page for pagination

    :param cve_per_page: number of cves listed on page
    :rtype: int
    :return integer that has a value 25, 50 or 100
    :Author: Karlo Kegljevic <kkegljev@carnet.hr>
    '''
    if cve_per_page:
        if not str(cve_per_page).isnumeric():
            return 25
        elif int(cve_per_page) > 75:
            return 100
        elif int(cve_per_page) > 37:
            return 50
        else:
            return 25
    else:
        return 25

def parse_page_no(page_no):
    '''Parses page number for pagination

    :param page_no: page number for pagination
    :rtype: int
    :Author: Karlo Kegljevic <kkegljev@carnet.hr>
    '''
    if page_no and str(page_no).isnumeric():
        return int(page_no)
    else:
        return 0

#METHODS FOR generate and read token and preparing for [un]confirm link sending on email
def generate_random_string(string_length=10):
    """Returns a random string of length string_length."""
    random = str(uuid.uuid4()) # Convert UUID format to a Python string.
    random = random.upper() # Make all characters uppercase.
    random = random.replace("-","") # Remove the UUID '-'.
    return random[0:string_length] # Return the random string.

def generate_confirmation_param(param):
    serializer = URLSafeTimedSerializer(env.get("SECRET_KEY"))
    return serializer.dumps(param, salt=env.get("SECRET_PASSWORD_SALT"))


def build_confirm_param(param):
    expiration = env.get("LINK_EXPIRATION_VALUE")
    serializer = URLSafeTimedSerializer(env.get("SECRET_KEY"))
    param = serializer.loads(
            param,
            salt=env.get("SECRET_PASSWORD_SALT"),
            max_age=int(expiration)
    )
    return param

#METHODS FOR mailing

def generate_email_body(template_file, data):
    file_path  = os.path.dirname(os.path.dirname(os.path.abspath(os.path.dirname(__file__))))
    templateLoader = jinja2.FileSystemLoader(searchpath=file_path + "/cert_epsilon/templates/emails/")
    templateEnv = jinja2.Environment(autoescape=True, loader=templateLoader)
    template = templateEnv.get_template(template_file)

    host = "https://" + env.get("HOST")
    return template.render(data=data, host=host)

def send_email(data, template, subject):
    email_body = generate_email_body(template, data)
    message = MIMEText(email_body, "html")
    message.add_header('Content-Type', 'text/html')
    message['Subject'] = subject
    message['From'] = env.get("EMAIL_FROM")
    message['To'] = data["email"]
    s = smtplib.SMTP(env.get("SMTP_HOST"), env.get("SMTP_PORT"))
    s.connect(env.get("SMTP_HOST"), env.get("SMTP_PORT"))
    s.ehlo()
    #s.starttls()
    #s.login(env.get("SMTP_USERNAME"), env.get("SMTP_PASSWORD"))
    #s = smtplib.SMTP(env.get("HOST"))
    s.sendmail(env.get("EMAIL_FROM"), data["email"], message.as_string())
    s.quit()

if __name__ == '__main__':
    print("This is a module! You cant run it as a standalone executable!")
    sys.exit(1)
else:
    load_dotenv()

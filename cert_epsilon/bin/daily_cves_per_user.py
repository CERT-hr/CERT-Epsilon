import sys

sys.path.append("../")

from lib.db_handler import db_handler
from lib import utils

def main():
    print("Starting collecting daily cves per subscribed users...")
    subscribed_users = db_handler.get_all_users()
    for user in subscribed_users:
        user_cves = db_handler.get_user_cves(user["user_id"])
        if len(user_cves) > 0:
            utils.send_email({"email": user["email"], "cves": user_cves, "action": ""},
                             "ncert_daily_sub_list_report_email.html", "NCERT - obavijesti o ranjivostima")

    print("Finish collecting daily cves per subscriped user, exiting ...")

if __name__ == '__main__':
    main()
else:
    print("daily_cves_per_user.py is used as a standalone executable!")
    sys.exit(1)

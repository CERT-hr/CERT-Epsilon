from flask import Blueprint, render_template, redirect, session, request, flash, jsonify
from flask_babel import refresh, _
from flask_paginate import Pagination, get_page_args
from cert_epsilon import app
from cert_epsilon.lib.db_handler import db_handler
from cert_epsilon.forms import SubscriptionForm, UnsubscriptionForm
from cert_epsilon.lib import utils
from os import environ as env
from dotenv import load_dotenv
from cert_epsilon.lib.utils import parse_cve_per_page, parse_page_no
from datetime import datetime, timedelta 
import random, json

main = Blueprint('main_views', __name__, url_prefix='/')

config_dict = {'languages': app.create_app().config["BABEL_LANGUAGE_LIST"]}

load_dotenv()

# LANGUAGE
@main.route('/lang/<language>')
def change_language(language):
    session['lang'] = language
    refresh()
    return redirect(request.referrer)

# STATIC ROUTES 
#=====================================================================
@main.route('/about')
def about():
    return render_template('about.html', config_dict=config_dict)

@main.route('/accessibility')
def accessibility():
    return render_template('accessibility.html', config_dict=config_dict)

@main.route('/terms-of-use')
def terms():
    return render_template('terms_of_use.html', config_dict=config_dict)
#=====================================================================

@main.route('/')
def index():
    try:
        page, per_page, trashcan = get_page_args(page_parameter='p', per_page_parameter='pp')
    except Exception:
        page=None
        per_page=None

    if not page:
        page = 1
    else:
        page=int(page)
    if not per_page:
        per_page = 25
    else:
        per_page=int(per_page)
    offset = page*per_page - per_page
    
    if request.args.get("q"):
        cves = db_handler.get_cves(request.args.get("q"))
    elif any(x in request.args for x in ["date_mode", "cvss", "os", "vendor"]):
        cves = db_handler.filter_cves(request.args)
    else:
        cves = db_handler.get_cves(".")
    total = len(cves)-1
    cves_ = cves[offset:offset+per_page]
    if len(cves) > 0 and (page*per_page-1) > total:
        print(page*per_page)
        print(page)
        print(total)
        page = 1
        offset = 0
        cves_ = cves[offset:per_page]

    pagination = Pagination(
                    page=page, per_page=per_page, page_parameter='p', per_page_parameter='pp',
                    total=total, css_framework='bootstrap4', show_single_page=True)
    oses = {}
    for os_type in db_handler.get_operating_system_types():
        oses[os_type] = db_handler.get_operation_system_by_type(os_type)
    return render_template('index.html', 
                            cves=cves_,
                            top_10_cves=db_handler.get_cve_top_ten(), 
                            oses=oses, 
                            per_page=per_page,
                            pagination=pagination, 
                            n_of_pages=int(total/per_page)+1,
                            config_dict=config_dict)

@main.route('/cve/<cve_id>')
def cve(cve_id):
    return render_template('cve.html',cve=db_handler.get_cve(cve_id), config_dict=config_dict)


@main.route('/cwe')
def cwe():
    try:
        page, per_page, trashcan = get_page_args(page_parameter='p', per_page_parameter='pp')
    except Exception:
        page=None
        per_page=None

    if not page:
        page = 1
    else:
        page=int(page)
    if not per_page:
        per_page = 25
    else:
        per_page=int(per_page)
    
    if request.args.get("q"):
        cwes = db_handler.get_cwes(request.args.get("q"))
    else:
        cwes = db_handler.get_all_cwe()

    offset = page*per_page - per_page
    total = len(cwes)
    cwes = cwes[offset:offset+per_page]
    if page*per_page > total:
        page = int(total/per_page) - 1

    pagination = Pagination(
                    page=page, per_page=per_page, page_parameter='p', per_page_parameter='pp',
                    total=total, css_framework='bootstrap4', show_single_page=True)

    return render_template('cwe.html', cwes=cwes, pagination=pagination, config_dict=config_dict)

@main.route('/cwe/<cwe_id>')
def cwe_details(cwe_id):
    data = {}
    data['cwe'] = db_handler.get_cwe(cwe_id)
    data['capec'] = db_handler.get_capec_for_cwe(cwe_id)
    if data['cwe']:
        return render_template("cwe-id.html", data=data, config_dict=config_dict)
    else:
        return_text = _("CWE with id '")+str(cwe_id)+_("' not found")
        return render_template("404.html", text=return_text, config_dict=config_dict)

@main.route('/capec/<capec_id>')
def capec_details(capec_id):
    capec = db_handler.get_capec(capec_id)
    return render_template(
            "capec.html", 
            capec_id=capec_id,
            capec_name=capec['name'],
            capec_summary=capec['description'],
            capec_prereqs=capec['prerequisites'],
            capec_solutions=capec['mitigations'], 
            config_dict=config_dict)

@main.route('/vendors')
def vendors():
    try:
        page, per_page, trashcan = get_page_args(page_parameter='p', per_page_parameter='pp')
    except Exception:
        page=None
        per_page=None
    
    if not page:
        page = 1
    else:
        page=int(page)
    if not per_page:
        per_page = 15
    else:
        per_page=int(per_page)
    q = request.args.get("q")
    vendors = []
    total = 0
    offset = page*per_page - per_page
    vendors = db_handler.get_all_vendors()

    top_all_vendors = db_handler.get_vendor_top_ten()
    top_weekly_vendors = db_handler.get_vendor_top_ten("weekly")
    if q:
        vendors = db_handler.get_vendors(q)
        if vendors:
            total = len(vendors)
            vendors = vendors[offset:offset+per_page]
    else:
        vendors = db_handler.get_vendors_in_range(offset, per_page)
        total = db_handler.get_vendor_count()
    if page*per_page > total:
        page = int(total/per_page) + 1
    for vendor in vendors:
        vendor['vulns'] = db_handler.get_vendor_cves(vendor['name'])

    pagination = Pagination(
                    page=page, per_page=per_page, page_parameter='p', per_page_parameter='pp',
                    total=total, css_framework='bootstrap4', show_single_page=True)

    return render_template(
                "vendors.html", 
                config_dict=config_dict,
                top_weekly_vendors=top_weekly_vendors,
                top_all_vendors=top_all_vendors,
                per_page=per_page,
                pagination=pagination,
                vendors=vendors,
                n_of_pages=int(total/per_page)+1,
                last_weeks_date=(datetime.today()-timedelta(days=7)).strftime('%Y-%m-%d')
            )

@main.route('/subscriptions', methods=['GET', 'POST'])
def subscriptions():
    os_list = {}
    sub_ids = []
    os_count = 0
    form = SubscriptionForm()
    config_dict["max_advanced_subscription"] = env.get("MAX_ADVANCED_SUBSCRIPTION")
    operation_system_types = db_handler.get_operating_system_types()
    for os_type in operation_system_types:
        operating_systems = db_handler.get_operation_system_by_type(os_type)
        os_list[os_type] = operating_systems
        os_count = os_count + int(len(operating_systems))
        control_os_count = 0
    if request.method == 'POST' and form.validate():
        data = request.form.to_dict()
        regex = data["regex"] if data["regex"] != "" else '.'
        user_id = db_handler.get_user(data["email"])
        if not user_id:
            user_id = db_handler.insert_user(data["email"])
        for i in range(os_count):
            if "os_list-" + str(i) + "-os" in data:
                if data["cvss"] == "":
                    form.cvss.errors.append("CVSS vezan za operacijski sustav nije zadan")
                    return render_template(
                        'subscriptions.html',
                        os_list=os_list,
                        form=form,
                        config_dict=config_dict)
                control_os_count = control_os_count + 1
                product_ids = db_handler.get_product_ids_from_name(data["os_list-" + str(i) + "-os"])
                for prod_id in product_ids:
                    vendor_id = db_handler.get_product_by_id(prod_id)["id_vendor"]
                    sub_id = db_handler.insert_subscription(regex, data["cvss"], False, user_id, prod_id, vendor_id)
                    if sub_id:
                        sub_ids.append(sub_id)
        if control_os_count == 0 and data["cvss"] != "":
            form.os_list.errors.append("Operacijski sustav nije zadan")
            return render_template(
                'subscriptions.html',
                os_list=os_list,
                form=form,
                config_dict=config_dict)

        control_advanced_vendor_count = 0
        for i in range(int(data["vendor-product-number"])):
            # if data["vpc-" + str(i) + "-vendorField"] not in redis_query.vendors():
            #     error = "Uneseni proizvođač ne postoji."
            #     return render_template('subscription.html', form=subscription_form, message=redis_query.vendors(),
            #                            r=0, **self.args)
            # if data["vpc-" + str(i) + "-productField"] != "":
            #     if data["vpc-" + str(i) + "-productField"] not in redis_query.vendor_products(
            #             data["vpc-" + str(i) + "-vendorField"]):
            #         error = "Proizvod " + data["vpc-" + str(i) + "-productField"] + " ne odgovara proizvođaču " + \
            #                 data["vpc-" + str(i) + "-vendorField"] + "."
            #         return render_template('subscription.html', form=subscription_form, message=error, r=0,
            #                                **self.args)
            selected_product = None
            selected_cvss = None

            if data["vpc-" + str(i) + "-vendorField"] != "":
                if data["vpc-" + str(i) + "-cvssField"] != "":
                    selected_cvss = data["vpc-" + str(i) + "-cvssField"]
                if data["vpc-" + str(i) + "-productField"] != "":
                    selected_product = data["vpc-" + str(i) + "-productField"]
                    selected_product = db_handler.get_product(selected_product)["product_id"]
                vendor_id = db_handler.get_vendor(data["vpc-" + str(i) + "-vendorField"])["vendor_id"]
                sub_id = db_handler.insert_subscription(regex, selected_cvss, False, user_id, selected_product, vendor_id)
                control_advanced_vendor_count = control_advanced_vendor_count + 1
                if sub_id:
                    sub_ids.append(sub_id)
            #TODO: add else when autocomplete bug will be fixed

        if (control_os_count == 0 and data["cvss"] == "") and control_advanced_vendor_count == 0:
            form.vpc.errors.append("Nije zadana niti jedna opcija pretplate bilo da se radi o zadavanju operativnog sustava ili bilo kojeg proizvođača preko napredne opcije")
            return render_template(
                'subscriptions.html',
                os_list=os_list,
                form=form,
                config_dict=config_dict)

        id_ = utils.generate_confirmation_param(data["email"])
        token = utils.generate_confirmation_param(sub_ids)

        utils.send_email({"email": data["email"], "id": id_, "token": token, "action": "confirm_subscriptions"},
                         "ncert_sub_conf_mail.html", "NCERT - mail potvrde prijave na liste")
        flash('Uspješno ste izvršili prijavu na liste te će Vam na zadani email biti poslan link za potvrdu za pretplate')
        return redirect('/subscriptions')

    return render_template(
            'subscriptions.html',
            os_list=os_list,
            form=form,
            config_dict=config_dict)


@main.route('/confirm_subscriptions')
def confirm_subscsriptions():
    try:
        email = utils.build_confirm_param(request.args.get('id'))
    except:
        flash('Link za potvrdu preplata je neispravan ili je istekao.')
    try:
        sub_ids = utils.build_confirm_param(request.args.get('token'))
    except:
        flash('Link za potvrdu preplata je neispravan ili je istekao.')

    user_id = db_handler.get_user(email)
    if not user_id:
        flash('Link za potvrdu preplata je neispravan ili je istekao.')
        return redirect('/subscriptions')
    for sub_id in sub_ids:
        sub = db_handler.get_subscription_by_id(sub_id)
        if sub["confirmed"] == True:
            flash('Link za potvrdu preplata je neispravan ili je istekao.')
            return redirect('/subscriptions')
        else:
            db_handler.confirm_subscription(sub_id)

    flash('Uspjesno se potvrdili preplatu na liste')
    return redirect('/subscriptions')

@main.route('/request_subscription_list/<email>')
def request_subscription_list(email):
    user_id = db_handler.get_user(email)
    if user_id:
        #example format[{id_vendor: 1, id_product: 1, cvss: 2.0}]
        user_sub_list = db_handler.get_user_subscriptions(user_id)
        #we sending email whatever if user exist or not in database
        utils.send_email({"email": email, "list": user_sub_list, "action": ""},
                         "ncert_sub_list_mail.html", "NCERT - popis pretplata")
    message = 'Na zadanu adresu elektroničke pošte je poslana lista na kojima ste trenutno preplaćeni.'
    return json.dumps({"message": message})

@main.route('/request_unsubscriptions/<email>')
def request_unsubscriptions(email):
    token = utils.generate_confirmation_param(email)
    utils.send_email({"email": email, "token": token, "action": "unsubscriptions"},
                     "ncert_unsub_conf_mail.html", "NCERT - zahtjev za odjavom za pretplate")
    message = 'Uspjesno se poslan zahtjev za odjavom sa lista za preplatu na vas email'
    return json.dumps({"message": message})

@main.route('/unsubscriptions', methods=['GET', 'POST'])
def unsubscriptions():
    form = UnsubscriptionForm()
    if request.method == 'POST' and form.validate():
        data = request.form.to_dict()
        del_sub_count = 0
        for i in range(session['subs_count']):
            selected_key = "subscription_list-" + str(i) + "-sub_item"
            if selected_key in data:
                db_handler.delete_subscription(data[selected_key])
                del_sub_count = del_sub_count + 1
        if session['subs_count'] == del_sub_count:
            db_handler.delete_user(session["email"])
        if del_sub_count == 0:
            form.subscription_list.errors.append("Morate oznaciti barem jednu prijavu")
            return render_template(
                'unsubscriptions.html',
                subscriptions=session['subs'],
                email=session["email"],
                form=form,
                config_dict=config_dict)
        flash('Uspješno ste izvršili odjavu sa svih selektiranih liste')
        return redirect('/subscriptions')
    else:
        try:
            session["email"] = utils.build_confirm_param(request.args.get('token'))
        except:
            flash('Link za zahtjevom za odjavu od pretplata je neispravan ili je istekao.')

        user_id = db_handler.get_user(session["email"])
        if not user_id:
            flash('Link za zahtjevom za odjavu od pretplata je neispravan ili je istekao.')
            return redirect('/subscriptions')

        session['subs'] = db_handler.get_user_subscriptions(user_id)
        session['subs_count'] = len(session['subs'])

        return render_template(
            'unsubscriptions.html',
                subscriptions=session['subs'],
                email=session["email"],
                form=form,
                config_dict=config_dict)

@main.route('/vendor/<vend>')
def vendor_info(vend):
    return 'TBA single page with info for vendor'

@main.route('/api/get_vendors')
def get_vendors():
    return jsonify(db_handler.get_all_vendors())

@main.route('/api/get_products_for_vendor')
def get_products_for_vendor():
    return jsonify(db_handler.get_products_for_vendor(request.args.get('vendor')))

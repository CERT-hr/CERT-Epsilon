# WebForms #
from flask_wtf import Form
from wtforms import StringField, BooleanField, DecimalField, SubmitField, FieldList
from wtforms import PasswordField, ValidationError, BooleanField, HiddenField, FormField
from wtforms.validators import DataRequired, Email, Length, Regexp, EqualTo, Optional, NumberRange

class OperatingSystemForm(Form):
    os = BooleanField(validators = [])

class VendorProductCVSSForm(Form):
    productField = StringField(u'Proizvod')
    vendorField = StringField('Proizvo ^qa ^m', validators = [])
    cvssField = DecimalField('CVSS',  validators=[Optional()], filters = [lambda x: x or None])


class SubscriptionForm(Form):
    os_list = FieldList(FormField(OperatingSystemForm), min_entries=0, max_entries=30)
    cvss = DecimalField('CVSS',  validators=[Optional()], filters = [lambda x: x or None])
    regex = StringField('Regularni izraz', validators = [])
    vpc = FieldList(FormField(VendorProductCVSSForm), min_entries=0, max_entries=30)
    email = StringField('Upišite Vašu adresu elektroničke pošte',
                        validators=[DataRequired(),
                                    Email(),
                                    Length(1, 64),
                                    Regexp('^([a-zA-Z0-9_\-\.]+)@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([a-zA-Z0-9\-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$', 0,
                                           'Invalid email format.')])

    submit = SubmitField('Preplata na zadane liste')

    def __init__(self, *args, **kwargs):
        super(SubscriptionForm, self).__init__(*args, **kwargs)
        self.cvss.data = 0.0


class SubscriptionListForm(Form):
    sub_item = BooleanField()

class UnsubscriptionForm(Form):
    subscription_list=FieldList(FormField(SubscriptionListForm), min_entries=1, max_entries=30)
    submit = SubmitField('Odjava za zadane liste')

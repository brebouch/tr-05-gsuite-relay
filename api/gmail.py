#####################################
#
# Gmail Functions for parsing inbox
#
#####################################

from datetime import datetime, timedelta
import json
import base64
import re
import hashlib
import email
from email.message import EmailMessage
from google.oauth2 import service_account
from oauth2client.service_account import ServiceAccountCredentials
from googleapiclient.discovery import build
from jsonpath_ng import jsonpath, parse
import api.xdr as xdr


class Gmail:
    # Get Auth Token
    def get_credential(self, svc_act_json, delegated_email):
        return service_account.Credentials.from_service_account_info(
            svc_act_json, scopes=self.scopes, subject=delegated_email)

    # Get mail query string
    def get_mail_query(self):
        before = datetime.utcnow()
        after = before - timedelta(days=self.look_back)
        after = str(after.timestamp()).split('.')[0]
        before = str(before.timestamp()).split('.')[0]
        return f'after:{after} before:{before}'

    # Base64 decode string
    def decode_b64_string(self, b64):
        return base64.urlsafe_b64decode(b64)

    # Get Attachment Hash
    def get_string_hash(self, string):
        md5 = hashlib.md5(string)
        sha1 = hashlib.sha1(string)
        return {'md5': md5.hexdigest(), 'SHA1': sha1.hexdigest()}

    # Look for link in msg body
    def search_msg_for_url(self, msg):
        urls = re.findall('https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', msg)
        return urls

    # Get attachment details
    def get_attachment_hash(self, email_address, msg_id, attach_id):
        with build('gmail', 'v1', credentials=self.credentials) as service:
            attachments = []
            a = service.users().messages().attachments().get(userId=email,
                                                             messageId=msg_id,
                                                             id=attach_id).execute()
            return self.get_string_hash(self.decode_b64_string(a['data']))

    # Check msg attachments
    def get_message_relations(self, msg):
        relations = []
        mime: EmailMessage = email.message_from_bytes(self.decode_b64_string(msg['raw']), _class=EmailMessage)
        sender = mime['from']
        recipient = mime['to']
        subject = mime['subject']
        email_object = {'type': 'email_subject', 'value': subject}
        relations.append(
            xdr.set_relation(email_object, {'type': 'email_messageid', 'value': msg['id']}, 'related-to', 'Gmail'))
        try:
            sender_object = {'type': 'email', 'value': sender.split('<')[1].split('>')[0]}
        except:
            sender_object = {'type': 'email', 'value': sender}
        relations.append(xdr.set_relation(sender_object, email_object, 'sent-message', 'Gmail'))
        try:
            recipient_object = {'type': 'email', 'value': recipient.split('<')[1].split('>')[0]}
        except:
            recipient_object = {'type': 'email', 'value': recipient}
        relations.append(xdr.set_relation(email_object, recipient_object, 'received-message', 'Gmail'))
        urls = []
        for w in mime.walk():
            try:
                if not w.is_attachment():
                    urls += self.search_msg_for_url(w.get_body().as_string())
            except Exception as e:
                continue
        for u in urls:
            url_object = {'type': 'url', 'value': u}
            relations.append(xdr.set_relation(email_object, url_object, 'related-to', 'Gmail'))
        attachments = list(mime.iter_attachments())
        if attachments:
            for a in attachments:
                data = self.get_string_hash(self.decode_b64_string(a.get_payload()))
                file_object = {'type': 'file_name', 'value': a.get_filename()}
                relations.append(xdr.set_relation(email_object, file_object, 'attached-to', 'Gmail'))
                relations.append(
                    xdr.set_relation(file_object, {'type': 'md5', 'value': data['md5']}, 'derived-from',
                                     'Gmail'))
                relations.append(
                    xdr.set_relation(file_object, {'type': 'md5', 'value': data['md5']}, 'derived-from',
                                     'Gmail'))
        return relations

    # Get users messages
    def get_messages(self, email_address):
        with build('gmail', 'v1', credentials=self.credentials) as service:
            sightings = []
            email_object = {'type': 'email', 'value': email_address}
            messages = service.users().messages().list(userId=email_address, q=self.get_mail_query()).execute()
            for m_id in messages['messages']:
                sighting = xdr.get_sighting_doc(self.module_name, f'Gmail message sighting for {email_address}')
                sighting['observables'] = [email_object]
                message = service.users().messages().get(userId=email_address, id=m_id['id'], format='raw').execute()
                relations = self.get_message_relations(message)
                if relations:
                    sighting['relations'] = relations
                    sightings.append(sighting)
            if sightings:
                observe = xdr.get_model()
                observe['sightings']['count'] = len(sightings)
                observe['sightings']['docs'] = sightings
                return observe
            return []

    def __init__(self, srv_act_json, delegated_email, look_back=4):
        self.module_name = 'Google Workspaces Integration Module'
        self.look_back = look_back
        self.scopes = [
            'https://www.googleapis.com/auth/gmail.readonly',
            'https://www.googleapis.com/auth/apps.alerts'
        ]
        self.credentials = self.get_credential(srv_act_json, delegated_email)


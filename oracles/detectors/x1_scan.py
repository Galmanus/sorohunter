import json,os,glob
env=json.load(open("rs-soroban-env/soroban-env-common/env.json"))
mods=env["modules"] if isinstance(env,dict) and "modules" in env else env
NAME={(mod.get("export"),fn.get("export")):fn.get("name") for mod in mods for fn in mod.get("functions",[])}
def analyze(path):
    b=open(path,'rb').read()
    if b[:4]!=b'\0asm':return None
    def leb(o,signed=False):
        r=s=0
        while True:
            x=b[o];o+=1;r|=(x&0x7f)<<s;s+=7
            if not x&0x80:break
        if signed and s<64 and (x&0x40):r|=-(1<<s)
        return r,o
    o=8;imp=[];code_off=None
    while o<len(b):
        sid=b[o];o+=1;ln,o=leb(o);end=o+ln
        if sid==2:
            n,p=leb(o)
            for _ in range(n):
                ml,p=leb(p);mod=b[p:p+ml].decode('latin1');p+=ml
                nl,p=leb(p);nm=b[p:p+nl].decode('latin1');p+=nl
                k=b[p];p+=1
                if k==0:_,p=leb(p);imp.append((mod,nm))
                elif k==1:p+=1;lim=b[p];p+=1;_,p=leb(p)
                elif k==2:
                    lim=b[p];p+=1;_,p=leb(p)
                    if lim==1:_,p=leb(p)
                elif k==3:p+=2
            o=end
        elif sid==10:code_off=o;o=end
        else:o=end
    ni=len(imp)
    tc={i for i in range(ni) if NAME.get(imp[i])=="try_call"}
    if not tc or code_off is None:return (ni,0,0,0)
    def bt(o):_,o=leb(o,1);return o
    def skip(op,o):
        if op in(0x02,0x03,0x04):return bt(o)
        if op in(0x0c,0x0d):_,o=leb(o);return o
        if op==0x0e:
            n,o=leb(o)
            for _ in range(n+1):_,o=leb(o)
            return o
        if op==0x10:_,o=leb(o);return o
        if op==0x11:_,o=leb(o);_,o=leb(o);return o
        if op in(0x20,0x21,0x22,0x23,0x24,0x25,0x26):_,o=leb(o);return o
        if 0x28<=op<=0x3e:_,o=leb(o);_,o=leb(o);return o
        if op in(0x3f,0x40):return o+1
        if op in(0x41,0x42):_,o=leb(o,1);return o
        if op==0x43:return o+4
        if op==0x44:return o+8
        if op==0xd0:return o+1
        if op==0xd2:_,o=leb(o);return o
        if op==0x1c:
            n,o=leb(o);return o+n
        if op==0xfc:
            sub,o=leb(o)
            if sub==8:_,o=leb(o);o+=1
            elif sub in(9,13):_,o=leb(o)
            elif sub==10:o+=2
            elif sub==11:o+=1
            elif sub in(12,14):_,o=leb(o);_,o=leb(o)
            elif sub in(15,16,17):_,o=leb(o)
            return o
        return o
    o=code_off;nfn,o=leb(o);sites=0;checked=0
    for fi in range(nfn):
        sz,o=leb(o);fend=o+sz;nl,o=leb(o)
        for _ in range(nl):_,o=leb(o);o+=1
        st=[]
        while o<fend:
            op=b[o];o0=o;o=skip(op,o+1);st.append((o0,op))
        for k,(o0,op) in enumerate(st):
            if op==0x10:
                idx,_=leb(o0+1)
                if idx in tc:
                    sites+=1
                    # wider window: 14 ops. tag check = a const-3 followed (anywhere in window) by an eq/ne,
                    # with a preceding and-255 (i32 or i64). Covers i64 and i32.wrap paths + save-to-local.
                    got_and=False;got3=False;got_cmp=False
                    for j in range(k+1,min(k+15,len(st))):
                        oo,oop=st[j]
                        if oop in(0x83,0x71):  # i64.and / i32.and
                            got_and=True
                        if oop in(0x41,0x42):
                            v,_=leb(oo+1,1)
                            if v==3:got3=True
                        if oop in(0x51,0x52,0x46,0x47):  # i64.eq/ne, i32.eq/ne
                            got_cmp=True
                    if got_and and got3 and got_cmp:checked+=1
    return (ni,len(tc),sites,checked)
targets=["ae0da5a84b15805c","11329c2469455f5a","bfab576fb405952f","ae3409a4090bc087",
         "4b3d9f6b09f7127b","cad725da76353b34","f1077e0b77da5e62","12fca5a7a9657727"]
files={os.path.basename(f)[:16]:f for f in glob.glob("**/*.wasm",recursive=True)}
print(f"{'wasm':16}  sites checked  verdict")
for h in targets:
    f=files.get(h)
    if not f:print(f"{h}  (no local wasm)");continue
    r=analyze(f)
    if not r:continue
    ni,ntc,sites,checked=r
    verd="SAFE" if sites and checked==sites else ("X-1 CANDIDATE" if sites>checked else "-")
    print(f"{h}   {sites:^4} {checked:^6}  {verd}  [{checked}/{sites}]")

import sys,json,os
env=json.load(open("rs-soroban-env/soroban-env-common/env.json"))
mods=env["modules"] if isinstance(env,dict) and "modules" in env else env
NAME={(mod.get("export"),fn.get("export")):fn.get("name") for mod in mods for fn in mod.get("functions",[])}
b=open(sys.argv[1],'rb').read()
def leb(o,signed=False):
    r=s=0
    while True:
        x=b[o];o+=1;r|=(x&0x7f)<<s;s+=7
        if not x&0x80:break
    if signed and s<64 and (x&0x40):r|=-(1<<s)
    return r,o
# --- sections ---
o=8;secs={}
imp_fns=[]   # ordered function-kind imports -> (module,name)
n_imported=0
code_off=None
while o<len(b):
    sid=b[o];o+=1;ln,o=leb(o);end=o+ln
    if sid==2:
        n,p=leb(o)
        for _ in range(n):
            ml,p=leb(p);mod=b[p:p+ml].decode('latin1');p+=ml
            nl,p=leb(p);nm=b[p:p+nl].decode('latin1');p+=nl
            k=b[p];p+=1
            if k==0:
                _,p=leb(p); imp_fns.append((mod,nm))
            elif k==1:p+=1;_,p=leb(p);_,p=leb(p) if False else (0,p)  # table (skip crude)
            elif k==2:
                lim=b[p];p+=1;_,p=leb(p)
                if lim==1:_,p=leb(p)
            elif k==3:p+=2
        o=end
    elif sid==10:
        code_off=o;o=end
    else:o=end
n_imported=len(imp_fns)
# target import indices
targets={i:NAME.get(imp_fns[i],f"{imp_fns[i][0]}.{imp_fns[i][1]}?") for i in range(n_imported)}
want={i:nm for i,nm in targets.items() if nm in ("call","try_call")}
print(f"imported host fns: {n_imported}; call/try_call indices: {want}")

# --- opcode immediate decoder ---
def blocktype(o):
    _,o=leb(o,signed=True);return o
def skip(op,o):
    if op in (0x02,0x03,0x04): return blocktype(o)
    if op in (0x0c,0x0d): _,o=leb(o);return o
    if op==0x0e:
        n,o=leb(o)
        for _ in range(n+1):_,o=leb(o)
        return o
    if op==0x10:_,o=leb(o);return o
    if op==0x11:_,o=leb(o);_,o=leb(o);return o
    if op in (0x20,0x21,0x22,0x23,0x24,0x25,0x26):_,o=leb(o);return o
    if 0x28<=op<=0x3e:_,o=leb(o);_,o=leb(o);return o
    if op in (0x3f,0x40):o+=1;return o
    if op==0x41:_,o=leb(o,1);return o
    if op==0x42:_,o=leb(o,1);return o
    if op==0x43:return o+4
    if op==0x44:return o+8
    if op==0xd0:o+=1;return o
    if op==0xd2:_,o=leb(o);return o
    if op==0x1c:
        n,o=leb(o)
        return o+n
    if op==0xfc:
        sub,o=leb(o)
        if sub in (8,):_,o=leb(o);o+=1
        elif sub in (9,13):_,o=leb(o)
        elif sub==10:o+=2
        elif sub==11:o+=1
        elif sub in (12,14):_,o=leb(o);_,o=leb(o)
        elif sub in (15,16,17):_,o=leb(o)
        return o
    return o  # 0-immediate ops
OPN={0x10:"call",0x11:"call_indirect",0x1a:"drop",0x21:"local.set",0x22:"local.tee",0x20:"local.get",
     0x41:"i32.const",0x42:"i64.const",0x0d:"br_if",0x04:"if",0x0b:"end",0x83:"i64.and",0x84:"i64.or",
     0x86:"i64.shl",0x88:"i64.shr_u",0x87:"i64.shr_s",0x51:"i64.eq",0x52:"i64.ne",0x45:"i32.eqz",
     0x71:"i32.and",0x50:"i64.eqz",0x36:"i32.store",0x37:"i64.store"}
def opname(op,o0,o1):
    nm=OPN.get(op,hex(op))
    if op==0x10:
        idx,_=leb(o0+1)
        tgt=("HOST:"+targets[idx]) if idx<n_imported else f"func{idx}"
        return f"call {tgt}"
    if op in (0x41,0x42):
        v,_=leb(o0+1,1);return f"{OPN[op]} {v}"
    if op in (0x20,0x21,0x22):
        v,_=leb(o0+1);return f"{OPN[op]} {v}"
    return nm

# --- walk code section, record instr stream per fn, flag try_call sites ---
o=code_off
nfn,o=leb(o)
sites=[]
for fi in range(nfn):
    sz,o=leb(o);fend=o+sz
    nl,o=leb(o)
    for _ in range(nl):_,o=leb(o);o+=1
    stream=[]
    while o<fend:
        op=b[o];o0=o;o=skip(op,o+1);stream.append((o0,op))
    # find call to try_call/call host
    for k,(o0,op) in enumerate(stream):
        if op==0x10:
            idx,_=leb(o0+1)
            if idx in want:
                sites.append((n_imported+fi, want[idx], k, stream))
print(f"\ntry_call/call host sites: {len([s for s in sites if s[1]=='try_call'])} try_call, {len([s for s in sites if s[1]=='call'])} call")
for gi,nm,k,stream in sites:
    if nm!="try_call":continue
    print(f"\n--- func{gi}  {nm} site  (next 10 ops after result) ---")
    for j in range(k,min(k+11,len(stream))):
        o0,op=stream[j]
        print(f"   {opname(op,o0,o0)}")

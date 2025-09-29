# xeon_post_dual.py
import sys, re, collections

if len(sys.argv) < 3:
    print("usage: python3 xeon_post_dual.py xeon_samples.csv resolved_raw.txt [xeon_stacks.addr] [out_stacks.sym]")
    sys.exit(1)

samples_csv, resolved_txt = sys.argv[1], sys.argv[2]
stacks_addr = sys.argv[3] if len(sys.argv) >= 4 else None
stacks_sym  = sys.argv[4] if len(sys.argv) >= 5 else None

# ip -> (cnt, cyc, ns)
ip_data = {}
with open(samples_csv) as f:
    for line in f:
        ip, cnt, cyc, ns = line.strip().split(",")
        ip_data[ip] = (int(cnt), int(cyc), int(ns))

# addr -> function
addr2func = {}
sym_re = re.compile(r'^ADDR\s+(0x[0-9a-fA-F]+)\s+->\s+(.+?)\s+in section')
with open(resolved_txt) as f:
    for line in f:
        m = sym_re.match(line.strip())
        if m:
            addr = m.group(1)
            func = m.group(2).split('+')[0].strip()
            addr2func[addr] = func

# aggregate by function
by_func_cnt = collections.Counter()
by_func_cyc = collections.Counter()
by_func_ns  = collections.Counter()
unk_cnt = unk_cyc = unk_ns = 0

for ip,(cnt,cyc,ns) in ip_data.items():
    fn = addr2func.get(ip)
    if fn:
        by_func_cnt[fn] += cnt
        by_func_cyc[fn] += cyc
        by_func_ns[fn]  += ns
    else:
        unk_cnt += cnt; unk_cyc += cyc; unk_ns += ns

tot_cnt = sum(by_func_cnt.values()) + unk_cnt
tot_cyc = sum(by_func_cyc.values()) + unk_cyc
tot_ns  = sum(by_func_ns.values())  + unk_ns

# Print table, sorted by cycles
rows = []
for fn in set(list(by_func_cyc.keys()) + list(by_func_cnt.keys()) + list(by_func_ns.keys())):
    cnt = by_func_cnt[fn]
    cyc = by_func_cyc[fn]
    ns  = by_func_ns[fn]
    pct_cyc = (100.0*cyc/tot_cyc) if tot_cyc else 0.0
    pct_ns  = (100.0*ns/tot_ns)   if tot_ns  else 0.0
    rows.append((fn, cnt, cyc, pct_cyc, ns, pct_ns))

rows.sort(key=lambda x: x[2], reverse=True)
w = max([len(r[0]) for r in rows]+[10])
print(f"{'Function'.ljust(w)}  Samples     Cycles       %Cyc      Time(ns)      %Time")
print("-"*w + "  --------  ------------  -------  -------------  ------")
for fn,cnt,cyc,pct_cyc,ns,pct_ns in rows:
    print(f"{fn.ljust(w)}  {cnt:8d}  {cyc:12d}  {pct_cyc:6.2f}%  {ns:13d}  {pct_ns:6.2f}%")
if unk_cnt or unk_cyc or unk_ns:
    print(f"{'[unresolved]'.ljust(w)}  {unk_cnt:8d}  {unk_cyc:12d}            {unk_ns:13d}")

# Optional: symbolicate collapsed stacks
if stacks_addr and stacks_sym:
    def symline(line):
        path,count = line.rsplit(" ",1)
        addrs = path.split(";")
        names = [addr2func.get(a, a) for a in addrs]
        return ";".join(names) + " " + count
    with open(stacks_addr) as f, open(stacks_sym,"w") as g:
        for line in f:
            line=line.strip()
            if not line: continue
            g.write(symline(line)+"\n")
    print(f"Wrote symbolicated stacks: {stacks_sym}")

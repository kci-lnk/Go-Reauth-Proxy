#!/usr/bin/env python3
"""Run baseline/candidate proxy test workers on Linux, without production config.

Build both test executables with identical memory_acceptance_test.go (copy only
that file to the base checkout), Go toolchain, GOARCH and CGO_ENABLED. Example:
  go test -c -o candidate.test ./pkg/proxy
  python3 tools/memorycheck/run.py --base ./baseline.test --candidate ./candidate.test --output results --mode all
Workers listen on OS-assigned loopback ports. Ctrl-C/any failure stops workers.
"""
import argparse
import json
import os
from pathlib import Path
import statistics
import subprocess
import time
import urllib.request

P = argparse.ArgumentParser(description=__doc__)
P.add_argument('--base', required=True)
P.add_argument('--candidate', required=True)
P.add_argument('--output', required=True)
P.add_argument('--mode', choices=['perf', 'memory', 'bench', 'all'], default='all')
P.add_argument('--rounds', type=int, default=6)
P.add_argument('--seconds', type=float, default=2)
P.add_argument('--case', action='append', dest='cases', help='Repeat only scenario/concurrency/protocol, e.g. slow/64/2')
P.add_argument('--idle-seconds', type=int, default=300)
P.add_argument('--bench-pattern', default='BenchmarkAcceptanceWire')
P.add_argument('--bench-time', default='1s')
args = P.parse_args()
root = Path(args.output).resolve()
root.mkdir(parents=True, exist_ok=True)
bins = {k: str(Path(v).resolve()) for k,v in [('base',args.base),('candidate',args.candidate)]}
env = dict(os.environ, GOMAXPROCS='4', GOGC='100', GOMEMLIMIT='off')
workers = []

def emit(kind, data):
    record = dict(kind=kind, time=time.time(), **data)
    with (root / 'samples.jsonl').open('a') as out: out.write(json.dumps(record)+'\n')
    return record

def get(url):
    with urllib.request.urlopen(url, timeout=60) as response: return json.load(response)

class Worker:
    def __init__(self, name, role, upstream=''):
        self.log = (root / f'{name}-{role}.stderr').open('a')
        self.p = subprocess.Popen([bins[name], '-test.run=^TestMemoryAcceptanceWorker$', '-test.timeout=0'],
            env=dict(env, FN_KNOCK_MEMORY_WORKER=role, FN_KNOCK_MEMORY_UPSTREAM=upstream),
            stdout=subprocess.PIPE, stderr=self.log, text=True)
        workers.append(self)
        line = self.p.stdout.readline()
        if not line: raise RuntimeError(f'worker failed: {name}/{role}')
        self.info = json.loads(line)
        self.url = self.info['url']; self.control = self.info['control']
    def sample(self):
        data = get(self.control+'/snapshot')
        status = dict(line.split(':',1) for line in Path(f'/proc/{self.p.pid}/status').read_text().splitlines() if ':' in line)
        data.update({key:int(status[key].split()[0])*1024 for key in ['VmRSS','VmHWM','VmSwap']})
        stat = Path(f'/proc/{self.p.pid}/stat').read_text().split(') ',1)[1].split()
        data['cpu_seconds'] = (int(stat[11])+int(stat[12])) / os.sysconf('SC_CLK_TCK')
        return data
    def close(self):
        if self.p.poll() is None:
            self.p.terminate()
            try: self.p.wait(timeout=10)
            except subprocess.TimeoutExpired: self.p.kill(); self.p.wait()
        self.p.stdout.close(); self.log.close()

def client(name, worker, scenario, concurrency, http2, seconds):
    process = subprocess.Popen([bins['base'], '-test.run=^TestMemoryAcceptanceWorker$', '-test.timeout=90s'],
        env=dict(env,FN_KNOCK_MEMORY_WORKER='client',FN_KNOCK_MEMORY_TARGET=worker.url+'/'+('known' if scenario=='slow' else scenario),
                 FN_KNOCK_MEMORY_CONCURRENCY=str(concurrency),FN_KNOCK_MEMORY_SECONDS=str(seconds),
                 FN_KNOCK_MEMORY_HTTP2=str(int(http2)),FN_KNOCK_MEMORY_SLOW=str(int(scenario=='slow'))),
        stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    try:
        if process.stdout.readline().strip() != 'READY':
            raise RuntimeError('client did not finish warmup')
        before=worker.sample()
        process.stdin.write('start\n'); process.stdin.flush()
        stdout,stderr=process.communicate(timeout=65)
        if process.returncode: raise RuntimeError(f'client failed: {stdout} {stderr}')
        after=worker.sample()
        line=next(line[7:] for line in stdout.splitlines() if line.startswith('RESULT '))
        return dict(json.loads(line),_before=before,_after=after)
    finally:
        if process.poll() is None: process.kill(); process.wait()
        for stream in [process.stdin,process.stdout,process.stderr]: stream.close()

def perf():
    rows=[]
    upstream=Worker('base','upstream')
    try:
        proxies={name:Worker(name,'proxy',upstream.url) for name in bins}
        for name,w in proxies.items(): client(name,w,'unknown',16,True,1)
        cases=[(s,c,h) for s in ['small','known','unknown'] for c in [1,16,64] for h in [False,True]]
        cases += [('slow',c,True) for c in [1,16,64]]
        if args.cases:
            requested=set(args.cases)
            available={f'{s}/{c}/{2 if h else 1}' for s,c,h in cases}
            if requested-available: raise ValueError(f'unknown cases: {requested-available}')
            cases=[(s,c,h) for s,c,h in cases if f'{s}/{c}/{2 if h else 1}' in requested]
        for round_id in range(args.rounds):
            order=['base','candidate'] if round_id%2==0 else ['candidate','base']
            for scenario,c,h in cases:
                for name in order:
                    w=proxies[name]
                    result=client(name,w,scenario,c,h,args.seconds)
                    before=result.pop('_before'); after=result.pop('_after'); n=result['requests']
                    result.update(bytes_per_op=(after['total_alloc']-before['total_alloc'])/n,
                                  allocs_per_op=(after['mallocs']-before['mallocs'])/n,
                                  cpu_seconds=after['cpu_seconds']-before['cpu_seconds'],rss=after['VmRSS'],peak_rss=after['VmHWM'])
                    rows.append(emit('perf',dict(revision=name,round=round_id,scenario=scenario,concurrency=c,http2=h,**result)))
            print(f'performance round {round_id+1}/{args.rounds} complete',flush=True)
        summary=[]
        for scenario,c,h in cases:
            group={name:[r for r in rows if (r['revision'],r['scenario'],r['concurrency'],r['http2'])==(name,scenario,c,h)] for name in bins}
            med={name:{key:statistics.median(r[key] for r in rs) for key in ['mib_s','p95_ms','bytes_per_op','allocs_per_op','rss','peak_rss']} for name,rs in group.items()}
            a,b=med['base'],med['candidate']
            changes={key:b[key]/a[key]-1 if a[key] else 0 for key in a}
            passed=changes['mib_s']>=-0.03 and changes['p95_ms']<=0.03 and changes['bytes_per_op']<=0.05 and b['allocs_per_op']<=a['allocs_per_op']*1.05+1
            summary.append(dict(scenario=scenario,concurrency=c,http2=h,medians=med,changes=changes,passed=passed))
        (root/'performance.json').write_text(json.dumps(summary,indent=2))
        print(f"performance gate: {sum(s['passed'] for s in summary)}/{len(summary)} cases passed",flush=True)
        return all(s['passed'] for s in summary)
    finally:
        for w in list(workers): w.close()
        workers.clear()

def memory():
    upstream=Worker('base','upstream')
    try:
        for name in bins:
            w=Worker(name,'proxy',upstream.url)
            try:
                emit('memory',dict(revision=name,phase='baseline',**w.sample()))
                get(w.control+'/burst?controlled=1')
                emit('memory',dict(revision=name,phase='controlled_burst',**w.sample()))
                time.sleep(40)
                get(w.control+'/gc')
                emit('memory',dict(revision=name,phase='controlled_after_one_gc',**w.sample()))
                with urllib.request.urlopen(w.control+'/heap') as response: (root/f'{name}-heap.pb.gz').write_bytes(response.read())
                # Natural recovery is a separate phase with no forced GC.
                get(w.control+'/burst')
                start=time.monotonic()
                while True:
                    elapsed=time.monotonic()-start
                    emit('memory',dict(revision=name,phase='natural_idle',elapsed=elapsed,**w.sample()))
                    if elapsed>=args.idle_seconds: break
                    time.sleep(min(10,args.idle_seconds-elapsed))
                    if int(elapsed)%60<10: print(f'{name}: natural idle {int(elapsed)}s/{args.idle_seconds}s',flush=True)
                get(w.control+'/burst')
                emit('memory',dict(revision=name,phase='second_burst',**w.sample()))
                get(w.control+'/gc')
                emit('memory',dict(revision=name,phase='second_burst_one_gc',**w.sample()))
                print(f'{name}: memory phases complete',flush=True)
            finally: w.close();workers.remove(w)
    finally:
        for w in list(workers): w.close()
        workers.clear()

def bench():
    pattern=args.bench_pattern
    for round_id in range(-1,args.rounds):
        for name in (['base','candidate'] if round_id%2==0 else ['candidate','base']):
            result=subprocess.run([bins[name],'-test.run=^$','-test.bench='+pattern,'-test.benchmem','-test.benchtime='+args.bench_time,'-test.count=1'],env=env,capture_output=True,text=True,check=True)
            if round_id>=0:
                with (root/f'{name}.bench').open('a') as f: f.write(result.stdout)
        print(f'benchmark round {round_id+1}/{args.rounds} complete (0=warmup)',flush=True)

performance_passed = True
try:
    emit('environment',dict(uname=list(os.uname()),settings={k:env[k] for k in ['GOMAXPROCS','GOGC','GOMEMLIMIT']},binaries=bins))
    if args.mode in ['perf','all']: performance_passed = perf()
    if args.mode in ['memory','all']: memory()
    if args.mode in ['bench','all']: bench()
finally:
    for worker in workers: worker.close()

if not performance_passed:
    raise SystemExit("performance gate failed; see performance.json")

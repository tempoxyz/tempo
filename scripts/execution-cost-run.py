"""Measurement-only branch: identical fixtures, CPU affinity, paired runs, overhead controls."""
import json, os, pathlib, shutil, subprocess
root = pathlib.Path.cwd()
out = root / 'execution-cost-results'
out.mkdir(exist_ok=True)
cpu = min(os.sched_getaffinity(0))
(out/'environment.txt').write_text(subprocess.check_output(['lscpu'], text=True)+f'\npinned_cpu={cpu}\n'+subprocess.check_output(['rustc','+nightly','-Vv'], text=True))
binaries = {}
for backend in ['revm','native']:
    (out/f'{backend}-ref.txt').write_text(subprocess.check_output(['git','rev-parse','HEAD'], cwd=root/backend,text=True))
    for instrumented in [False,True]:
        label = backend + ('-instrumented' if instrumented else '-plain')
        cmd = ['cargo','+nightly','bench','--no-run','--profile','profiling','-p','tempo-evm','--bench','execution_cost','--message-format=json']
        if instrumented: cmd += ['--features','execution-measure']
        env = dict(os.environ, CARGO_TARGET_DIR=str(root/'execution-cost-target'))
        with (out/f'{label}-build.log').open('w') as log:
            process = subprocess.Popen(cmd,cwd=root/backend,env=env,stdout=subprocess.PIPE,stderr=log,text=True)
            executable = None
            for line in process.stdout:
                log.write(line)
                try: event = json.loads(line)
                except ValueError: continue
                if event.get('reason') == 'compiler-artifact' and event.get('target',{}).get('name') == 'execution_cost' and event.get('executable'):
                    executable = event['executable']
            assert process.wait() == 0, f'{label} build failed'
        assert executable, label
        dest = out/label
        shutil.copy2(executable,dest)
        binaries[label] = str(dest)
def run(label, name, mode, hook=True, validate=False, rounds=128, perf=False, cache="cold"):
    env = dict(os.environ, MEASURE_MODE=str(mode), MEASURE_ROUNDS=str(rounds), MEASURE_TX_CACHE=cache)
    if hook: env['MEASURE_HOOK']='1'
    if validate:
        env.update(MEASURE_VALIDATE='1', MEASURE_STATE_ROWS=str(out/f'{name}-state.rows'), MEASURE_OUTPUT_ROWS=str(out/f'{name}-output.rows'))
    cmd = ['taskset','-c',str(cpu),binaries[label]]
    if perf:
        control, ack = out/f'{name}-control', out/f'{name}-ack'
        os.mkfifo(control); os.mkfifo(ack)
        env.update(MEASURE_PERF_CONTROL=str(control), MEASURE_PERF_ACK=str(ack))
        cmd = ['perf','stat','--delay=-1',f'--control=fifo:{control},{ack}', '-x',',','-o',str(out/f'{name}-perf.csv'),'-e','cycles,instructions,branches,branch-misses,cache-misses']+cmd
    with (out/f'{name}.log').open('w') as log:
        subprocess.run(cmd,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
    if perf: control.unlink(); ack.unlink()
for cache in ['cold','warm']:
    for backend in ['revm','native']:
        run(backend+'-plain', backend+'-'+cache+'-validate',0,validate=True,rounds=1,cache=cache)
    for suffix in ['state','output']:
        assert (out/f'revm-{cache}-validate-{suffix}.rows').read_bytes()==(out/f'native-{cache}-validate-{suffix}.rows').read_bytes(), f'{cache} {suffix} mismatch'
# Fresh transaction data is cloned outside timing for both engines; hash caches are explicit.
for cache in ['cold','warm']:
    for pair in range(3):
        order = ['revm','native'] if pair%2==0 else ['native','revm']
        for hook in [False, True]:
            for label,mode in [('plain',0),('instrumented',0),('instrumented',1),('instrumented',2),('instrumented',3)]:
                for backend in order:
                    name=f'p{pair}-{backend}-{cache}-{label}-m{mode}-hook{int(hook)}'
                    run(f'{backend}-{label}',name,mode,hook=hook,cache=cache)
# Retired hardware counters corroborate total CPU cost without per-transaction clock calls.
for backend in ['revm','native']:
    run(backend+'-plain',backend+'-hardware',0,rounds=512,perf=True)

# Keep artifacts small: raw data and build logs, rather than four identical large binaries.
for binary in binaries.values(): pathlib.Path(binary).unlink()

/* Use Afl.print instead of console.log */
Afl.print('******************');
Afl.print('* AFL FRIDA MODE *');
Afl.print('******************');
Afl.print('');

/* Print some useful diagnostics stuff */
Afl.print(`PID: ${Process.id}`);

const cm = new CModule(`

    #include <string.h>
    #include <gum/gumdefs.h>

    void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
      uint32_t input_buf_len) {

      memcpy((void *)regs->rdi, input_buf, input_buf_len);
      regs->rsi = input_buf_len;

    }
    `,
    {
        memcpy: Module.getExportByName(null, 'memcpy')
    });
Afl.setPersistentHook(cm.afl_persistent_hook);




new ModuleMap().values().forEach(m => {
    Afl.print(`${m.base}-${m.base.add(m.size)} ${m.name}`);
});

/*
 * Configure entry-point, persistence etc. This will be what most
 * people want to do.
 */
const persistent_addr = DebugSymbol.fromName('fuzz_one_input');
Afl.print(`persistent_addr: ${persistent_addr.address}`);

if (persistent_addr.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol main');
}

const persistent_ret = DebugSymbol.fromName('aaa');
Afl.print(`persistent_ret: ${persistent_ret.address}`);

if (persistent_ret.address.equals(ptr(0))) {
    Afl.error('Cannot find symbol slow');
}

Afl.setPersistentAddress(persistent_addr.address);
Afl.setPersistentReturn(persistent_ret.address);
Afl.setPersistentCount(1000000);

/* Control instrumentation, you may want to do this too */
Afl.setInstrumentLibraries();
//const mod = Process.findModuleByName("libblogfuzz.so")
//Afl.addExcludedRange(mod.base, mod.size);

/* Some useful options to configure logging */
Afl.setStdOut("/data/local/tmp/stdout.txt");
Afl.setStdErr("/data/local/tmp/stderr.txt");

/* Show the address layout. Sometimes helpful */
Afl.setDebugMaps();

/*
 * If you are using these options, then things aren't going
 * very well for you.
 */
Afl.setInstrumentDebugFile("/data/local/tmp/instr.log");
Afl.setPrefetchDisable();
Afl.setInstrumentNoOptimize();
Afl.setInstrumentEnableTracing();
Afl.setInstrumentTracingUnique();
Afl.setStatsFile("/data/local/tmp/stats.txt");
Afl.setStatsInterval(1);

/* *ALWAYS* call this when you have finished all your configuration */
Afl.done();
Afl.print("done");

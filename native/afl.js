Afl.print(`[*] Starting FRIDA config for PID: ${Process.id}`);


const cm = new CModule(`
  #include <string.h>
  #include <gum/gumdefs.h>

  #define BUF_LEN 256

  void afl_persistent_hook(GumCpuContext *regs, uint8_t *input_buf,
    uint32_t input_buf_len) {

    uint32_t length = (input_buf_len > BUF_LEN) ? BUF_LEN : input_buf_len;
    memcpy((void *)regs->rdi, input_buf, length);
    regs->rsi = length;
  }
  `,
  {
    memcpy: Module.getExportByName(null, "memcpy")
  }
);


const pStartAddr = DebugSymbol.fromName("fuzz_one_input").address;
const retAddr = DebugSymbol.fromName("aaa").address;

Afl.setPersistentHook(cm.afl_persistent_hook);
Afl.setPersistentAddress(pStartAddr);
Afl.setEntryPoint(pStartAddr);
Afl.setPersistentReturn(retAddr);
//Afl.setPersistentCount(1000000);
Afl.setInMemoryFuzzing();
Afl.setInstrumentLibraries();
//Afl.setStdOut("/data/local/tmp/stdout.txt");
//Afl.setStdErr("/data/local/tmp/stderr.txt");
//Afl.setDebugMaps();
//Afl.setInstrumentDebugFile("/data/local/tmp/instr.log");
Afl.setPrefetchDisable();
Afl.setInstrumentNoOptimize();
//Afl.setInstrumentEnableTracing();
//Afl.setInstrumentTracingUnique();
//Afl.setStatsFile("/data/local/tmp/stats.txt");
//Afl.setStatsInterval(1);



Afl.done();
Afl.print("[*] All done!");

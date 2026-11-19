/* retro-trainer PLAN-handheld HH-23/HH-33: the arm64 dynarec's AOT form. new_dynarec.c includes
 * this file at its end, on the arm64 dynarec only, so it shares that file's statics; the shared code
 * reaches it through the aot_* hooks declared at that file's top.
 *
 * new_dynarec_aot_configure (new_dynarec.h; libretro.c calls it, for now with the M64P_AOT*
 * environment) chooses a mode, which takes effect at the next new_dynarec_init:
 * - "load": runs from the image dylib `image`: no code cache is mapped, and a block is installed
 *   from the image where the JIT would compile it (aot_install); a block the image lacks stops the
 *   process.
 * And, in an RT_TRACE build only (the Mac's, whose tools make images; an iOS core carries load
 * alone):
 * - "shape": the JIT, emitting AOT-shaped code: no block linking, no check_addr stop to a block's
 *   extent, helpers called through the hot state's aot_imports by index, dirty stubs that name
 *   themselves PC-relatively. Such a block holds no host address, so its bytes run anywhere.
 *   `log` names the file each compiled block is logged to (aot_block_compiled).
 * - "emit": re-emits the blocks of `log` (a shape run's) into the image `image`.code and .meta in
 *   plain RW memory, never executed, then exits the process. `corrupt` names one block to re-emit
 *   wrongly on purpose (aot_emit_all).
 * - "hybrid": "shape" with the image of "load" installed first, a miss compiled by the JIT and
 *   counted (and logged to `log`): a measurement of an image on a run it was not made from.
 * The image format and its checks are aot_image_header's. */
#include <dlfcn.h>
#include <unistd.h>
#if defined(RT_TRACE) && TARGET_OS_OSX // the iOS SDK has neither libproc.h nor mach_vm.h
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#endif

/* The compiler state a block's code depends on besides its words, as it stood when the compile
 * began: using_tlb, and stop_after_jal (a savestate carries it, and it ends a block after a JAL). */
#define AOT_FLAG_TLB 1
#define AOT_FLAG_STOP_AFTER_JAL 2
#define AOT_FLAG_SETS_STOP_AFTER_JAL 4 // the compile itself set stop_after_jal (junk, a jump in a delay slot)

/* The image's meta file, words little-endian: this header, then per block
 *   addr, slen, code_off, code_len, nentries, flags (AOT_FLAG_*), words[slen+1],
 *   entries[nentries] of (vaddr, reg32, dirty_off, clean_off, ht_replace).
 * The fields hot_state_size..count_per_op_denom_pot are the fingerprint a load refuses a
 * mismatch of: the hot state's layout the code addresses off FP, the import table's length, and
 * the timing constants the code bakes in. The core's own build (which orders aot_imports) is
 * not yet in it. */
struct aot_image_header {
  u_int magic, version;
  u_int hot_state_size, fp_imports, fp_mmap, import_count, count_per_op, count_per_op_denom_pot;
  u_int nblocks, code_size;
};
#define AOT_MAGIC 0x31415452 /* "RTA1" */
#define AOT_VERSION 1

struct aot_entry { u_int vaddr, reg32, dirty_off, clean_off, ht_replace; };
struct aot_block {
  u_int addr, slen, code_off, code_len, nentries, flags;
  const u_int *words;               // slen+1: the block's words and the one its end looked at
  const struct aot_entry *entries;
};

/* What new_dynarec_aot_configure last chose; aot_mode is its mode from new_dynarec_init on. */
static struct { int mode; char *image, *log; u_int corrupt; } aot_cfg;

static struct {
  unsigned long flag_differs, compiled, wraps, installs, misses, lookahead, orphans, emit_skipped, emit_differs;
} aot_stats;

static char *aot_strdup(const char *s)
{
  if(!s||!*s) return NULL;
  char *d=strdup(s);
  AOT_CHECK(d,"out of memory");
  return d;
}

void new_dynarec_aot_configure(const char *mode, const char *image, const char *log, u_int corrupt)
{
  int m=AOT_OFF;
  if(mode&&*mode) {
    if(!strcmp(mode,"load")) m=AOT_LOAD;
#ifdef RT_TRACE
    else if(!strcmp(mode,"shape")) m=AOT_SHAPE;
    else if(!strcmp(mode,"emit")) m=AOT_EMIT;
    else if(!strcmp(mode,"hybrid")) m=AOT_HYBRID;
    else AOT_CHECK(0,"the mode %s is none of load, shape, emit, hybrid",mode);
#else
    else AOT_CHECK(0,"the mode %s is not load, the only one a build without RT_TRACE has",mode);
#endif
  }
  aot_cfg.mode=m;
  free(aot_cfg.image); aot_cfg.image=aot_strdup(image);
  free(aot_cfg.log); aot_cfg.log=aot_strdup(log);
  aot_cfg.corrupt=corrupt;
}

static void aot_init_mode(void)
{
  aot_mode=aot_cfg.mode;
}

// emit writes plain RW memory and load runs only the image: neither maps the MAP_JIT cache
static int aot_maps_no_cache(void)
{
  return aot_mode==AOT_EMIT||aot_mode==AOT_LOAD;
}

static u_int aot_flags_now(void)
{
  return (using_tlb?AOT_FLAG_TLB:0)|(stop_after_jal?AOT_FLAG_STOP_AFTER_JAL:0);
}

/* new_dyna_start's first block: stock compiles 0xa4000040 at the cache's start and enters there;
 * the AOT forms enter it the way every later block is entered. */
void *new_dyna_first_block(void)
{
  if(aot_mode==AOT_OFF) {
    void *first=base_addr_rx;
    new_recompile_block(0xa4000040);
    return first;
  }
  return get_addr_ht(0xa4000040);
}

/* An AOT-shaped dirty stub's check (linkage_arm64.S verify_code_aot): the ll_entry whose dirty
 * stub is `stub`, verified as verify_code verifies the one it is handed. */
u_int verify_dirty_at(void *stub, u_int vaddr)
{
  u_int page,vpage;
  entry_pages(vaddr,&page,&vpage);
  struct ll_entry *head;
  for(head=jump_dirty[vpage];head;head=head->next)
    if(head->vaddr==vaddr&&(void*)(((intptr_t)head->addr-(intptr_t)base_addr)+(intptr_t)base_addr_rx)==stub)
      return verify_dirty(head);
  aot_stats.orphans++; // no entry names it: treat the code as dirty, which recompiles
  return vaddr;
}

static void aot_header(struct aot_image_header *h, u_int nblocks, u_int code_size)
{
  h->magic=AOT_MAGIC; h->version=AOT_VERSION;
  h->hot_state_size=(u_int)sizeof(struct new_dynarec_hot_state);
  h->fp_imports=(u_int)fp_aot_imports; h->fp_mmap=(u_int)fp_memory_map;
  h->import_count=(u_int)AOT_IMPORT_COUNT;
  h->count_per_op=g_dev.r4300.cp0.count_per_op;
  h->count_per_op_denom_pot=g_dev.r4300.cp0.count_per_op_denom_pot;
  h->nblocks=nblocks; h->code_size=code_size;
}

static void aot_vm_report(const char *when)
{
#if defined(RT_TRACE) && TARGET_OS_OSX
  mach_vm_address_t a=0; mach_vm_size_t size;
  vm_region_basic_info_data_64_t info; mach_msg_type_number_t count; mach_port_t object;
  int x=0,rwx=0,anon=0;
  for(;;) {
    count=VM_REGION_BASIC_INFO_COUNT_64;
    if(mach_vm_region(mach_task_self(),&a,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object)!=KERN_SUCCESS) break;
    if(info.protection&VM_PROT_EXECUTE) {
      // proc_regionfilename names the next file-backed region for an anonymous one, so ask for
      // the region's own record and check that it is this region's
      struct proc_regionwithpathinfo rp;
      int got=proc_pidinfo(getpid(),PROC_PIDREGIONPATHINFO,a,&rp,sizeof rp);
      int file=got==(int)sizeof rp&&rp.prp_prinfo.pri_address==a&&rp.prp_vip.vip_path[0];
      const char *path=rp.prp_vip.vip_path;
      x++;
      if(info.protection&VM_PROT_WRITE) { rwx++; fprintf(stderr,"new_dynarec AOT vm: rwx %llx+%llx %s\n",(unsigned long long)a,(unsigned long long)size,file?path:"(no file)"); }
      if(!file&&anon++<3) { fprintf(stderr,"new_dynarec AOT vm: executable, no file: %llx+%llx prot %x\n",(unsigned long long)a,(unsigned long long)size,info.protection); }
    }
    a+=size;
  }
  fprintf(stderr,"new_dynarec AOT vm (%s): %d executable regions, %d writable and executable, %d executable with no file\n",when,x,rwx,anon);
#else
  (void)when;
#endif
}

static FILE *aot_log; static char *aot_log_path; // shape, hybrid: the compile log

static void aot_report(const char *when)
{
  static const char *const name[]={"off","shape","hybrid","emit","load"};
  if(aot_mode==AOT_OFF) return;
  fprintf(stderr,"new_dynarec AOT (%s, %s): %lu compiled, %lu cache wraps, %lu installed, %lu missed, %lu passed over for their compile flags, %lu lookahead differs, %lu orphan stubs\n",
    name[aot_mode],when,aot_stats.compiled,aot_stats.wraps,aot_stats.installs,aot_stats.misses,aot_stats.flag_differs,aot_stats.lookahead,aot_stats.orphans);
  if(aot_log) fflush(aot_log);
  aot_vm_report(when);
}

#ifdef RT_TRACE
/**** shape, emit and hybrid: the Mac's tooling ****/
static u_int aot_compile_flags;
static u_int *aot_emit_source;   // emit: the words of the block being re-emitted
static u_char *aot_block_end;    // the end of the block just compiled, before `out` wraps
static struct aot_entry aot_entries[MAXBLOCK+1]; // the entry points of the block being compiled
static int aot_entry_count;

/* AOT: a compile reads entries of these arrays it did not write this time (past the block's
 * end), so without this its code would depend on the block compiled before it (measured: 6 of
 * snp1's 1623 blocks re-emitted differently from the JIT's before it). */
static void aot_clear_compiler_state(void)
{
  memset(insn,0,sizeof insn);
  memset(itype,0,sizeof itype);
  memset(opcode,0,sizeof opcode);
  memset(opcode2,0,sizeof opcode2);
  memset(bt,0,sizeof bt);
  memset(rs1,0,sizeof rs1);
  memset(rs2,0,sizeof rs2);
  memset(rt1,0,sizeof rt1);
  memset(rt2,0,sizeof rt2);
  memset(us1,0,sizeof us1);
  memset(us2,0,sizeof us2);
  memset(dep1,0,sizeof dep1);
  memset(dep2,0,sizeof dep2);
  memset(lt1,0,sizeof lt1);
  memset(imm,0,sizeof imm);
  memset(ba,0,sizeof ba);
  memset(likely,0,sizeof likely);
  memset(is_ds,0,sizeof is_ds);
  memset(ooo,0,sizeof ooo);
  memset(unneeded_reg,0,sizeof unneeded_reg);
  memset(unneeded_reg_upper,0,sizeof unneeded_reg_upper);
  memset(branch_unneeded_reg,0,sizeof branch_unneeded_reg);
  memset(branch_unneeded_reg_upper,0,sizeof branch_unneeded_reg_upper);
  memset(p32,0,sizeof p32);
  memset(pr32,0,sizeof pr32);
  memset(regmap_pre,0,sizeof regmap_pre);
  memset(constmap,0,sizeof constmap);
  memset(regs,0,sizeof regs);
  memset(branch_regs,0,sizeof branch_regs);
  memset(minimum_free_regs,0,sizeof minimum_free_regs);
  memset(needed_reg,0,sizeof needed_reg);
  memset(requires_32bit,0,sizeof requires_32bit);
  memset(wont_dirty,0,sizeof wont_dirty);
  memset(will_dirty,0,sizeof will_dirty);
  memset(ccadj,0,sizeof ccadj);
  memset(instr_addr,0,sizeof instr_addr);
  memset(link_addr,0,sizeof link_addr);
  memset(stubs,0,sizeof stubs);
}

static void aot_compile_begin(u_int **psource)
{
  if(aot_mode==AOT_OFF) return;
  aot_clear_compiler_state();
  if(aot_mode==AOT_EMIT) *psource=aot_emit_source; // the logged words, not guest memory
  else aot_compile_flags=aot_flags_now(); // emit sets them from the log
}

static void aot_note_entry(u_int vaddr, u_int reg32, void *dirty, void *clean, int ht_replace)
{
  if(aot_mode==AOT_OFF) return;
  AOT_CHECK(aot_entry_count<MAXBLOCK+1,"too many entry points in one block");
  struct aot_entry *e=&aot_entries[aot_entry_count++];
  e->vaddr=vaddr; e->reg32=reg32; e->ht_replace=ht_replace;
  e->dirty_off=(u_int)(uintptr_t)dirty; e->clean_off=(u_int)(uintptr_t)clean; // made offsets below
}

static void aot_note_block_end(u_char *end)
{
  aot_block_end=end;
}

static uint64_t aot_fnv(const void *p, size_t n)
{
  uint64_t h=1469598103934665603ULL;
  const unsigned char *b=(const unsigned char *)p;
  while(n--) { h^=*b++; h*=1099511628211ULL; }
  return h;
}

/* ---- shape: the compile log ---- */
static void aot_open_log(const char *path)
{
  if(aot_log&&(!path||strcmp(path,aot_log_path))) { fclose(aot_log); aot_log=NULL; free(aot_log_path); aot_log_path=NULL; }
  if(aot_log||!path) return; // a reset re-inits the dynarec: the same log goes on
  aot_log=fopen(path,"w");
  AOT_CHECK(aot_log,"cannot write %s",path);
  aot_log_path=aot_strdup(path);
}

/* ---- emit: the image being written ---- */
static u_char *aot_out_code; static size_t aot_out_code_len, aot_out_code_cap;
static u_int *aot_out_meta; static size_t aot_out_meta_len, aot_out_meta_cap;
static u_int aot_out_blocks;
static uint64_t aot_emit_expect_hash; static u_int aot_emit_expect_len;
static const u_int *aot_emit_true_words; // the words the image records (the source, unless corrupted)
static int aot_emit_expect_entries;

static void aot_meta_push(u_int w)
{
  if(aot_out_meta_len==aot_out_meta_cap) {
    aot_out_meta_cap=aot_out_meta_cap?aot_out_meta_cap*2:65536;
    aot_out_meta=(u_int*)realloc(aot_out_meta,aot_out_meta_cap*4);
    AOT_CHECK(aot_out_meta,"out of memory");
  }
  aot_out_meta[aot_out_meta_len++]=w;
}

static void aot_block_compiled(int addr, uintptr_t beginning)
{
  if(aot_mode==AOT_OFF) return;
  int n=aot_entry_count;
  aot_entry_count=0;
  if(stop_after_jal&&!(aot_compile_flags&AOT_FLAG_STOP_AFTER_JAL)) aot_compile_flags|=AOT_FLAG_SETS_STOP_AFTER_JAL;
  aot_stats.compiled++;
  if((u_char*)out<aot_block_end) aot_stats.wraps++;
  size_t len=(size_t)(aot_block_end-(u_char*)beginning);
  uint64_t h=aot_fnv((void*)beginning,len);
  int k;
  for(k=0;k<n;k++) { // absolute -> block-relative
    aot_entries[k].dirty_off-=(u_int)beginning;
    aot_entries[k].clean_off-=(u_int)beginning;
  }
  if((aot_mode==AOT_SHAPE||aot_mode==AOT_HYBRID)&&aot_log) {
    fprintf(aot_log,"%08x %d %u %u %016llx %d",(u_int)addr,slen,aot_compile_flags,(u_int)len,(unsigned long long)h,n);
    for(k=0;k<=slen;k++) fprintf(aot_log," %08x",source[k]);
    fputc('\n',aot_log);
  }
  if(aot_mode==AOT_EMIT) {
    if(aot_emit_source!=aot_emit_true_words) fprintf(stderr,"new_dynarec AOT emit: %08x re-emitted from corrupted words, on purpose\n",(u_int)addr);
    else if(len!=aot_emit_expect_len||h!=aot_emit_expect_hash||n!=aot_emit_expect_entries) {
      if(aot_stats.emit_differs++<10)
        fprintf(stderr,"new_dynarec AOT emit: %08x re-emits as %u bytes %016llx, the JIT ran %u bytes %016llx\n",
          (u_int)addr,(u_int)len,(unsigned long long)h,aot_emit_expect_len,(unsigned long long)aot_emit_expect_hash);
    }
    if(aot_out_code_len+len>aot_out_code_cap) {
      aot_out_code_cap=(aot_out_code_len+len)*2;
      aot_out_code=(u_char*)realloc(aot_out_code,aot_out_code_cap);
      AOT_CHECK(aot_out_code,"out of memory");
    }
    u_int off=(u_int)aot_out_code_len;
    memcpy(aot_out_code+off,(void*)beginning,len);
    aot_out_code_len+=len;
    aot_meta_push((u_int)addr); aot_meta_push((u_int)slen); aot_meta_push(off); aot_meta_push((u_int)len);
    aot_meta_push((u_int)n); aot_meta_push(aot_compile_flags);
    for(k=0;k<=slen;k++) aot_meta_push(aot_emit_true_words[k]);
    for(k=0;k<n;k++) {
      aot_meta_push(aot_entries[k].vaddr); aot_meta_push(aot_entries[k].reg32);
      aot_meta_push(aot_entries[k].dirty_off); aot_meta_push(aot_entries[k].clean_off);
      aot_meta_push((u_int)aot_entries[k].ht_replace);
    }
    aot_out_blocks++;
  }
}

/* emit: one block a shape log lists, as the record the log wrote */
struct aot_record { u_int addr, slen, flags, code_len, nentries; uint64_t code_hash, key; u_int *words; };

static int aot_record_cmp(const void *a, const void *b)
{
  const struct aot_record *x=(const struct aot_record *)a, *y=(const struct aot_record *)b;
  if(x->key!=y->key) return x->key<y->key?-1:1;
  if(x->addr!=y->addr) return x->addr<y->addr?-1:1;
  if(x->slen!=y->slen) return x->slen<y->slen?-1:1;
  if(x->flags!=y->flags) return x->flags<y->flags?-1:1;
  return memcmp(x->words,y->words,(x->slen+1)*4);
}

/* emit: re-emit each distinct block of the log aot_cfg.log into the image aot_cfg.image (.code and
 * .meta), checking each against the JIT's own compile of it, then exit the process: 0 when the
 * image was written, 3 when a block re-emits otherwise than the JIT ran it (or the JIT compiled one
 * block two ways), 4 when a block could not be emitted; on 3 or 4 no image is left behind. */
static void aot_emit_all(void)
{
  const char *in=aot_cfg.log, *outp=aot_cfg.image;
  AOT_CHECK(in&&outp,"emit needs a log to read and an image to write");
  FILE *f=fopen(in,"r");
  AOT_CHECK(f,"cannot read %s",in);
  size_t n=0,cap=0;
  struct aot_record *recs=NULL;
  unsigned long long hash;
  struct aot_record r;
  while(fscanf(f,"%x %u %u %u %llx %u",&r.addr,&r.slen,&r.flags,&r.code_len,&hash,&r.nentries)==6) {
    r.code_hash=hash;
    AOT_CHECK(r.slen>0&&r.slen<MAXBLOCK,"a block of %u words in %s",r.slen,in);
    r.words=(u_int*)calloc(r.slen+1+64,4); // zeros past the logged words, so no compile reads the heap
    AOT_CHECK(r.words,"out of memory");
    u_int k;
    for(k=0;k<=r.slen;k++) AOT_CHECK(fscanf(f,"%x",&r.words[k])==1,"a short record in %s",in);
    r.key=aot_fnv(r.words,(r.slen+1)*4)^((uint64_t)r.addr<<32)^r.slen^((uint64_t)r.flags<<24);
    if(n==cap) { cap=cap?cap*2:4096; recs=(struct aot_record*)realloc(recs,cap*sizeof *recs); AOT_CHECK(recs,"out of memory"); }
    recs[n++]=r;
  }
  fclose(f);
  qsort(recs,n,sizeof *recs,aot_record_cmp);
  /* aot_cfg.corrupt=<addr>: a red receipt for the image comparisons. The block at <addr> is
     re-emitted with its first ADDIU's immediate one higher, while the image records its true
     words, so the block installs and computes a wrong value. */
  u_int corrupt_addr=aot_cfg.corrupt;
  u_int *bad=NULL;
  size_t i,unique=0;
  for(i=0;i<n;i++) {
    if(i>0&&aot_record_cmp(&recs[i-1],&recs[i])==0) { // the same block compiled again
      if(recs[i].code_hash!=recs[i-1].code_hash||recs[i].code_len!=recs[i-1].code_len||recs[i].nentries!=recs[i-1].nentries) {
        if(aot_stats.emit_differs++<10)
          fprintf(stderr,"new_dynarec AOT emit: the JIT compiled %08x two ways: %u bytes %016llx and %u bytes %016llx\n",
            recs[i].addr,recs[i-1].code_len,(unsigned long long)recs[i-1].code_hash,recs[i].code_len,(unsigned long long)recs[i].code_hash);
      }
      continue;
    }
    unique++;
    aot_emit_source=recs[i].words;
    aot_emit_true_words=recs[i].words;
    if(corrupt_addr&&recs[i].addr==corrupt_addr&&!bad) {
      u_int k;
      bad=(u_int*)calloc(recs[i].slen+1+64,4);
      AOT_CHECK(bad,"out of memory");
      memcpy(bad,recs[i].words,(recs[i].slen+1)*4);
      for(k=0;k<recs[i].slen&&!((bad[k]>>26)==0x09&&((bad[k]>>16)&0x1f)!=0);k++); // an ADDIU that writes a register
      AOT_CHECK(k<recs[i].slen,"the block at %08x holds no ADDIU to corrupt",corrupt_addr);
      bad[k]=(bad[k]&0xffff0000)|((bad[k]+1)&0xffff);
      fprintf(stderr,"new_dynarec AOT emit: corrupting %08x: word %u %08x -> %08x\n",corrupt_addr,k,recs[i].words[k],bad[k]);
      aot_emit_source=bad;
    }
    using_tlb=(recs[i].flags&AOT_FLAG_TLB)!=0;
    stop_after_jal=(recs[i].flags&AOT_FLAG_STOP_AFTER_JAL)!=0;
    aot_compile_flags=recs[i].flags&~AOT_FLAG_SETS_STOP_AFTER_JAL;
    aot_emit_expect_hash=recs[i].code_hash; aot_emit_expect_len=recs[i].code_len;
    aot_emit_expect_entries=(int)recs[i].nentries;
    aot_entry_count=0;
    if(new_recompile_block_impl((int)recs[i].addr)!=0) { aot_stats.emit_skipped++; continue; }
    AOT_CHECK((u_int)slen==recs[i].slen,"%08x re-emits as %d words, the log says %u",recs[i].addr,slen,recs[i].slen);
  }
  // a skipped block (one at a TLB-mapped address: emit has no mapping to compile it under) would
  // be a miss in every load of this image
  int status=aot_stats.emit_differs?3:aot_stats.emit_skipped?4:0;
  char path[4096];
  fprintf(stderr,"new_dynarec AOT emit: %lu records, %lu blocks, %lu emitted (%lu bytes), %lu skipped, %lu differ from the JIT's\n",
    (unsigned long)n,(unsigned long)unique,(unsigned long)aot_out_blocks,(unsigned long)aot_out_code_len,aot_stats.emit_skipped,aot_stats.emit_differs);
  if(status) { // no image, not even an earlier one under this name
    snprintf(path,sizeof path,"%s.code",outp); unlink(path);
    snprintf(path,sizeof path,"%s.meta",outp); unlink(path);
    fprintf(stderr,"new_dynarec AOT emit: no image written\n");
    fflush(stderr);
    _exit(status);
  }
  struct aot_image_header h;
  aot_header(&h,aot_out_blocks,(u_int)aot_out_code_len);
  snprintf(path,sizeof path,"%s.code",outp);
  f=fopen(path,"wb"); AOT_CHECK(f,"cannot write %s",path);
  AOT_CHECK(fwrite(aot_out_code,1,aot_out_code_len,f)==aot_out_code_len,"short write %s",path); fclose(f);
  snprintf(path,sizeof path,"%s.meta",outp);
  f=fopen(path,"wb"); AOT_CHECK(f,"cannot write %s",path);
  AOT_CHECK(fwrite(&h,sizeof h,1,f)==1&&fwrite(aot_out_meta,4,aot_out_meta_len,f)==aot_out_meta_len,"short write %s",path);
  fclose(f);
  fflush(stderr);
  _exit(0);
}
#else
static void aot_compile_begin(u_int **psource) { (void)psource; } // load compiles nothing
static void aot_note_entry(u_int vaddr, u_int reg32, void *dirty, void *clean, int ht_replace)
{
  (void)vaddr; (void)reg32; (void)dirty; (void)clean; (void)ht_replace;
}
static void aot_note_block_end(u_char *end) { (void)end; }
static void aot_block_compiled(int addr, uintptr_t beginning) { (void)addr; (void)beginning; }
#endif

/**** load: the image ****/
static void *aot_lib; // the image's dylib, while one is loaded
static const u_char *aot_code;
static struct aot_block *aot_blocks; static u_int aot_nblocks;

static int aot_block_cmp(const void *a, const void *b)
{
  u_int x=((const struct aot_block *)a)->addr, y=((const struct aot_block *)b)->addr;
  return x<y?-1:x>y;
}

/* The image dylib at path, loaded for this init (aot_release_image drops it at cleanup). */
static void aot_load_image(const char *path)
{
  AOT_CHECK(path,"load needs an image");
  aot_lib=dlopen(path,RTLD_NOW|RTLD_LOCAL);
  AOT_CHECK(aot_lib,"dlopen %s: %s",path,dlerror());
  aot_code=(const u_char*)dlsym(aot_lib,"rt_aot_code");
  const u_int *meta=(const u_int*)dlsym(aot_lib,"rt_aot_meta");
  const u_int *meta_end=(const u_int*)dlsym(aot_lib,"rt_aot_meta_end");
  AOT_CHECK(aot_code&&meta&&meta_end,"%s lacks rt_aot_code/rt_aot_meta/rt_aot_meta_end",path);
  struct aot_image_header want, h;
  memcpy(&h,meta,sizeof h);
  aot_header(&want,h.nblocks,h.code_size);
  AOT_CHECK(!memcmp(&h,&want,sizeof h),
    "%s was emitted for another core (magic %x/%x v%u/%u, hot state %u/%u, imports at %u/%u, memory_map at %u/%u, %u/%u imports, count_per_op %u/%u, denom %u/%u)",
    path,h.magic,want.magic,h.version,want.version,h.hot_state_size,want.hot_state_size,h.fp_imports,want.fp_imports,
    h.fp_mmap,want.fp_mmap,h.import_count,want.import_count,h.count_per_op,want.count_per_op,h.count_per_op_denom_pot,want.count_per_op_denom_pot);
  const u_int *p=meta+sizeof h/4;
  aot_nblocks=h.nblocks;
  aot_blocks=(struct aot_block*)calloc(aot_nblocks,sizeof *aot_blocks);
  AOT_CHECK(aot_blocks,"out of memory");
  u_int i;
  for(i=0;i<aot_nblocks;i++) {
    struct aot_block *b=&aot_blocks[i];
    AOT_CHECK(p+6<=meta_end,"%s: meta ends inside block %u",path,i);
    b->addr=p[0]; b->slen=p[1]; b->code_off=p[2]; b->code_len=p[3]; b->nentries=p[4]; b->flags=p[5];
    b->words=p+6;
    b->entries=(const struct aot_entry*)(p+6+b->slen+1);
    p+=6+b->slen+1+5*b->nentries;
    AOT_CHECK(p<=meta_end&&b->code_off+b->code_len<=h.code_size,"%s: block %u overruns the image",path,i);
  }
  AOT_CHECK(p==meta_end,"%s: %ld words of meta after the last block",path,(long)(meta_end-p));
  qsort(aot_blocks,aot_nblocks,sizeof *aot_blocks,aot_block_cmp);
  fprintf(stderr,"new_dynarec AOT load: %s: %u blocks, %u bytes of code at %p\n",path,aot_nblocks,h.code_size,(void*)aot_code);
}

static void aot_release_image(void)
{
  free(aot_blocks); aot_blocks=NULL; aot_nblocks=0; aot_code=NULL;
  if(aot_lib) { dlclose(aot_lib); aot_lib=NULL; }
}

static void aot_init(void)
{
  if(aot_mode==AOT_OFF) return;
#ifdef RT_TRACE
  if(aot_mode==AOT_SHAPE||aot_mode==AOT_HYBRID) aot_open_log(aot_cfg.log);
  if(aot_mode==AOT_EMIT) aot_emit_all();
#endif
  if(aot_mode==AOT_LOAD||aot_mode==AOT_HYBRID) { aot_load_image(aot_cfg.image); aot_vm_report("image loaded"); }
}

/* new_dynarec_cleanup's: the run's report, then the image released, so the next init (a reset,
 * or another game's load) loads the image its configuration names. */
static void aot_cleanup(void)
{
  aot_report("end of run");
  aot_release_image();
  memset(&aot_stats,0,sizeof aot_stats);
}

/* load: where the JIT would compile the block at `addr`, install the image's block that starts
 * there and holds the words guest memory holds now, registered exactly as the compile would have
 * registered it (new_recompile_block_impl's pass 9, through the same entry_pages,
 * hash_table_replace and protect_block_pages). */
static int aot_install(int addr)
{
  u_int start=(u_int)addr&~3, limit;
  const u_int *src=block_source(addr,&limit);
  if(!src) return 1; // the caller raises the TLB miss
  struct aot_block key; key.addr=(u_int)addr;
  struct aot_block *b=(struct aot_block*)bsearch(&key,aot_blocks,aot_nblocks,sizeof key,aot_block_cmp);
  int candidates=0;
  if(b) {
    while(b>aot_blocks&&b[-1].addr==(u_int)addr) b--;
    for(;b<aot_blocks+aot_nblocks&&b->addr==(u_int)addr;b++) {
      candidates++;
      if(start+b->slen*4>limit||memcmp(src,b->words,b->slen*4)) continue;
      // compiled under other compiler state: the JIT would compile it otherwise now
      if((b->flags&~AOT_FLAG_SETS_STOP_AFTER_JAL)!=aot_flags_now()) { aot_stats.flag_differs++; continue; }
      if(b->flags&AOT_FLAG_SETS_STOP_AFTER_JAL) stop_after_jal=1; // as its compile did
      if(start+b->slen*4<limit&&src[b->slen]!=b->words[b->slen]) aot_stats.lookahead++;
      u_int len=b->slen*4, k;
      char *cp=(char*)malloc(len+4);
      AOT_CHECK(cp,"out of memory");
      memcpy(cp,src,len);
      ((u_int*)cp)[b->slen]=b->nentries; // copy's trailer: how many entries share it
      copy_size+=len+4;
      u_char *code=(u_char*)aot_code+b->code_off;
      for(k=0;k<b->nentries;k++) {
        const struct aot_entry *e=&b->entries[k];
        u_int page, vpage;
        entry_pages(e->vaddr,&page,&vpage);
        struct ll_entry *head=ll_add_32(jump_dirty+vpage,e->vaddr,e->reg32,code+e->dirty_off,NULL,start,cp,len);
        head->clean_addr=code+e->clean_off;
        struct ll_entry *in=ll_add_32(jump_in+page,e->vaddr,e->reg32,head->clean_addr,head->clean_addr,start,cp,len);
        if(e->ht_replace) hash_table_replace(e->vaddr,in);
      }
      protect_block_pages(start,len);
      aot_stats.installs++;
      return 0;
    }
  }
  aot_stats.misses++;
  if(aot_mode==AOT_HYBRID) return -1; // the JIT compiles it
  AOT_CHECK(0,"miss at %08x: the image holds %d block(s) starting there, none with its words (%08x %08x %08x %08x)",
    (u_int)addr,candidates,src[0],src[1],src[2],src[3]);
  return 1;
}

static int aot_from_image(int addr, int *ret)
{
  if(aot_mode==AOT_LOAD) { *ret=aot_install(addr); return 1; }
#ifdef RT_TRACE
  if(aot_mode==AOT_HYBRID) { int r=aot_install(addr); if(r>=0) { *ret=r; return 1; } } // else the JIT compiles it
#endif
  return 0;
}

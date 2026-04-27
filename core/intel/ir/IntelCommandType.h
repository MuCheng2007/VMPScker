#ifndef INTEL_COMMAND_TYPE_H
#define INTEL_COMMAND_TYPE_H

#include <cstdint>

enum IntelCommandType : uint16_t
{
	cmUnknown,cmPush,cmPop,cmMov,cmAdd,cmXor,cmTest,cmLea,
	cmUd0, cmRet,cmNor,cmNand,cmCrc,cmCall,cmJmp,cmFstsw,cmFsqrt,cmFchs,cmFstcw,cmFldcw,
	cmFild,cmFist,cmFistp,cmFld,cmFstp,cmFst,
	cmFadd,cmFsub,cmFsubr,cmFisub,cmFisubr,cmFdiv,cmFcomp,cmFmul,
	cmRepe,cmRepne,cmRep,cmDB,cmDW,cmDD,cmDQ,
	cmMovs,cmCmps,cmScas,
	cmMovzx,cmMovsx,

	cmInc,cmDec,
	cmLes,cmLds,cmLfs,cmLgs,cmLss,
	cmXadd,cmBswap,
	cmJmpWithFlag,
	cmAnd,cmSub,cmStos,cmLods,cmNop,cmXchg,
	cmPushf,cmPopf,cmSahf,cmLahf,cmShl,cmShr,cmSal,cmSar,cmRcl,cmRcr,cmRol,cmRor,cmShld,cmShrd,
	cmLoope,cmLoopne,cmLoop,cmJCXZ,
	cmIn,cmIns,cmOut,cmOuts,cmWait,
	cmCbw,cmCwde,cmCdqe,cmCwd,cmCdq,cmCqo,
	cmClc,cmStc,cmCli,cmSti,cmCld,cmStd,
	cmNot,cmNeg,cmDiv,cmImul,cmIdiv,cmMul,
	cmOr,cmAdc,cmCmp,cmSbb,
	cmPusha,cmPopa,

	cmClflush,cmPause,

	cmBound,cmArpl,cmDaa,cmDas,cmAaa,cmAam,cmAad,cmAas,cmEnter,cmLeave,cmInt,cmInto,cmIret,
	cmSetXX,cmCmov,

	cmAddpd,cmAddps,cmAddsd,cmAddss,
	cmAndpd,cmAndps,cmAndnpd,cmAndnps,
	cmCmppd,cmCmpps,cmCmpsd,cmCmpss,
	cmComisd,cmComiss,
	cmCvtdq2ps,cmCvtpd2dq,cmCvtdq2pd,cmCvtpd2pi,cmCvtps2pi,
	cmCvtpd2ps,cmCvtps2pd,cmCvtpi2pd,cmCvtpi2ps,cmCvtps2dq,
	cmCvtsd2si,cmCvtss2si,cmCvtsd2ss,cmCvtss2sd,
	cmCvttpd2pi,cmCvttps2pi,cmCvttpd2dq,cmCvttps2dq,
	cmCvttsd2si,cmCvttss2si,
	cmDivpd,cmDivps,cmDivsd,cmDivss,
	cmMaxpd,cmMaxps,cmMaxsd,cmMaxss,
	cmMinpd,cmMinps,cmMinsd,cmMinss,
	cmMulpd,cmMulps,cmMulsd,cmMulss,
	cmOrpd,cmOrps,

	cmMovd,cmMovq,cmMovntq,cmMovapd,cmMovaps,cmMovdqa,cmMovdqu,
	cmMovdq2q,cmMovq2dq,
	cmMovhlps,cmMovhpd,cmMovhps,cmMovlhps,cmMovlpd,cmMovlps,
	cmMovmskpd,cmMovmskps,
	cmMovnti,
	cmMovntpd,cmMovntps,
	cmMovsd,cmMovss,
	cmMovupd,cmMovups,

	cmPmovmskb,cmPsadbw,
	cmPshufw,cmPshufd,cmPshuflw,cmPshufhw,
	cmPsubb,cmPsubw,cmPsubd,cmPsubq,
	cmPsubsb,cmPsubsw,
	cmPsubusb,cmPsubusw,
	cmPaddb,cmPaddw,cmPaddd,cmPaddq,
	cmPaddsb,cmPaddsw,
	cmPaddusb,cmPaddusw,
	cmPavgb,cmPavgw,
	cmPinsrb,cmPinsrw,cmPinsrd,cmPinsrq,cmPextrw,
	cmPmaxsb,cmPmaxsw,cmPmaxsd,cmPmaxub,cmPmaxuw,cmPmaxud,
	cmPminsb,cmPminsw,cmPminsd,cmPminub,cmPminuw,cmPminud,
	cmPmulhuw,cmPmulhw,cmPmullw,cmPmuludq,cmPmulld,
	cmPsllw,cmPslld,cmPsllq,cmPslldq,
	cmPsraw,cmPsrad,
	cmPsrlw,cmPsrld,cmPsrlq,cmPsrldq,

	cmPunpcklbw,cmPunpcklwd,cmPunpckldq,cmPunpcklqdq,cmPunpckhqdq,

	cmPackusdw,cmPcmpgtb,cmPcmpgtw,cmPcmpgtd,cmPcmpeqb,cmPcmpeqw,cmPcmpeqd,cmEmms,
	cmPacksswb,cmPackuswb,cmPunpckhbw,cmPunpckhwd,cmPunpckhdq,cmPackssdw,cmPand,cmPandn,cmPor,cmPxor,cmPmaddwd,
	cmRcpps,cmRcpss,
	cmRsqrtss,cmMovsxd,
	cmShufps,cmShufpd,
	cmSqrtpd,cmSqrtps,cmSqrtsd,cmSqrtss,
	cmSubpd,cmSubps,cmSubsd,cmSubss,
	cmUcomisd,cmUcomiss,
	cmUnpckhpd,cmUnpckhps,
	cmUnpcklpd,cmUnpcklps,
	cmXorpd,cmXorps,

	cmBt,cmBts,cmBtr,cmBtc,cmXlat,cmCpuid,cmRsm,cmBsf,cmBsr,cmCmpxchg,cmCmpxchg8b,
	cmHlt,cmCmc,
	cmLgdt,cmSgdt,cmLidt,cmSidt,cmSmsw,cmLmsw,cmInvlpg,
	cmLar,cmLsl,cmClts,cmInvd,cmWbinvd,cmUd2,cmWrmsr,cmRdtsc,cmRdmsr,cmRdpmc,

	cmFcom,cmFdivr,
	cmFiadd,cmFimul,cmFicom,cmFicomp,cmFidiv,cmFidivr,
	cmFaddp,cmFmulp,cmFsubp,cmFsubrp,cmFdivp,cmFdivrp,
	cmFbld,cmFbstp,

	cmFfree,cmFrstor,cmFsave,cmFucom,cmFucomp,

	cmFldenv,cmFstenvm,
	cmFxch,cmFabs,cmFxam,
	cmFld1,cmFldl2t,cmFldl2e,cmFldpi,cmFldlg2,cmFldln2,

	cmFldz,cmFyl2x,cmFptan,cmFpatan,cmFxtract,cmFprem1,cmFdecstp,cmFincstp,
	cmFprem,cmFyl2xp1,cmFsincos,cmFrndint,cmFscale,cmFsin,cmFcos,cmFtst,
	cmFstenv,cmF2xm1,cmFnop,cmFinit,cmFclex,cmFcompp,

	cmSysenter,cmSysexit,cmSldt,cmStr,cmLldt,cmLtr,cmVerr,cmVerw,
	cmSfence,cmLfence,cmMfence,cmPrefetchnta,cmPrefetcht0,cmPrefetcht1,cmPrefetcht2,cmPrefetch,cmPrefetchw,
	cmFxrstor,cmFxsave,cmLdmxcsr,cmStmxcsr,

	cmFcmovb, cmFcmove, cmFcmovbe, cmFcmovu, cmFcmovnb, cmFcmovne, cmFcmovnbe, cmFcmovnu,

	cmFucomi,cmFcomi,
	cmFucomip,cmFcomip,cmFucompp,

	cmVmcall, cmVmlaunch, cmVmresume, cmVmxoff, cmMonitor, cmMwait, cmXgetbv, cmXsetbv, cmVmrun, cmVmmcall, 
	cmVmload, cmVmsave, cmStgi, cmClgi, cmSkinit, cmInvlpga, cmSwapgs, cmRdtscp, cmSyscall, cmSysret, cmFemms, cmGetsec,
	cmPshufb, cmPhaddw, cmPhaddd, cmPhaddsw, cmPmaddubsw, cmPhsubw, cmPhsubd, cmPhsubsw, cmPsignb, cmPsignw, cmPsignd, cmPmulhrsw,
	cmPabsb, cmPabsw, cmPabsd, cmMovbe, cmPalignr, cmRsqrtps, cmVmread, cmVmwrite, cmSvldt, cmRsldt, cmSvts, cmRsts,
	cmXsave, cmXrstor, cmVmptrld, cmVmptrst, cmMaskmovq, cmFnstenv, cmFnstcw, cmFstp1, cmFneni, cmFndisi, cmFnclex, cmFninit, 
	cmFsetpm, cmFisttp, cmFnsave, cmFnstsw, cmFxch4, cmFcomp5, cmFfreep, cmFxch7, cmFstp8, cmFstp9, cmHaddpd, cmHsubpd,
	cmAddsubpd, cmAddsubps, cmMovntdq, cmFcom2, cmFcomp3, cmHaddps, cmHsubps, cmMovddup, cmMovsldup, cmCvtsi2sd, cmCvtsi2ss, 
	cmMovntsd, cmMovntss, cmLddqu, cmMovshdup, cmPopcnt, cmTzcnt, cmLzcnt,
	cmPblendvb, cmPblendps, cmPblendpd, cmPblendw, cmPtest, cmPmovsxbw, cmPmovsxbd, cmPmovsxbq, cmPmovsxwd, cmPmovsxwq, cmPmovsxdq, cmPmuldq,
	cmPcmpeqq, cmMovntdqa, cmXsaveopt, cmMaskmovdqu, cmUd1, cmPcmpgtq, 
	cmAesdec, cmAesdeclast, cmAesenc, cmAesenclast, cmAesimc, cmAeskeygenassist,
	cmRdrand, cmRdseed,
	cmPmovzxbw, cmPmovzxbd, cmPmovzxbq, cmPmovzxwd, cmPmovzxwq, cmPmovzxdq,

	cmFnmadd132sd, cmFnmadd213sd, cmFnmadd231sd,
	cmFnmadd132ss, cmFnmadd213ss, cmFnmadd231ss,

	cmUleb,cmSleb,cmDC,
	cmVbroadcastss, cmVbroadcastsd, cmVbroadcastf128, cmVperm2f128, cmVpermilpd, cmVpermilps, cmRoundpd, cmRoundps, cmCrc32, cmPextrb, cmPextrd, cmPextrq, cmVzeroupper,
	cmVzeroall, cmBlendpd, cmBlendps, cmBlendvpd, cmBlendvps, cmDpps, cmExtractf128, cmInsertf128, cmMaskmovpd, cmMaskmovps,
	cmVtestps, cmVtestpd, cmPcmpistri
};

static const char *intel_command_name[] = {
	"db ??","push","pop","mov","add","xor","test","lea",
	"ud0", "ret","nor","nand","crc","call","jmp","fstsw","fsqrt","fchs","fstcw","fldcw",
	"fild","fist","fistp","fld","fstp","fst",
	"fadd","fsub","fsubr","fisub","fisubr","fdiv","fcomp","fmul",
	"repe","repne","rep","db","dw","dd","dq",
	"movs","cmps","scas",
	"movzx","movsx",

	"inc","dec",
	"les","lds","lfs","lgs","lss",
	"xadd","bswap",
	"j",
	"and","sub","stos","lods","nop","xchg",
	"pushf","popf","sahf","lahf","shl","shr","sal","sar","rcl","rcr","rol","ror","shld","shrd",
	"loope","loopne","loop","jcxz",
	"in","ins","out","outs","wait",
	"cbw","cwde","cdqe","cwd","cdq","cqo",
	"clc","stc","cli","sti","cld","std",
	"not","neg","div","imul","idiv","mul",
	"or","adc","cmp","sbb",
	"pusha","popa",

	"clflush","pause",

	"bound","arpl","daa","das","aaa","aam","aad","aas","enter","leave","int","into","iret",
	"set","cmov",
	"addpd","addps","addsd","addss",
	"andpd","andps","andnpd","andnps",
	"cmppd","cmpps","cmpsd","cmpss",
	"comisd","comiss",
	"cvtdq2ps","cvtpd2dq","cvtdq2pd","cvtpd2pi","cvtps2pi",
	"cvtpd2ps","cvtps2pd","cvtpi2pd","cvtpi2ps","cvtps2dq",
	"cvtsd2si","cvtss2si","cvtsd2ss","cvtss2sd",
	"cvttpd2pi","cvttps2pi","cvttpd2dq","cvttps2dq",
	"cvttsd2si","cvttss2si",
	"divpd","divps","divsd","divss",
	"maxpd","maxps","maxsd","maxss",
	"minpd","minps","minsd","minss",
	"mulpd","mulps","mulsd","mulss",
	"orpd","orps",

	"movd","movq","movntq","movapd","movaps","movdqa","movdqu",
	"movdq2q","movq2dq",
	"movhlps","movhpd","movhps","movlhps","movlpd","movlps",
	"movmskpd","movmskps",
	"movnti",
	"movntpd","movntps",
	"movsd","movss",
	"movupd","movups",

	"pmovmskb","psadbw",
	"pshufw","pshufd","pshuflw","pshufhw",
	"psubb","psubw","psubd","psubq",
	"psubsb","psubsw",
	"psubusb","psubusw",
	"paddb","paddw","paddd","paddq",
	"paddsb","paddsw",
	"paddusb","paddusw",
	"pavgb","pavgw",
	"pinsrb","pinsrw","pinsrd","pinsrq","pextrw",
	"pmaxsb","pmaxsw","pmaxsd","pmaxub","pmaxuw","pmaxud",
	"pminsb","pminsw","pminsd","pminub","pminuw","pminud",
	"pmulhuw","pmulhw","pmullw","pmuludq","pmulld",
	"psllw","pslld","psllq","pslldq",
	"psraw","psrad",
	"psrlw","psrld","psrlq","psrldq",
	"punpcklbw","punpcklwd","punpckldq","punpcklqdq","punpckhqdq",

	"packusdw","pcmpgtb","pcmpgtw","pcmpgtd","pcmpeqb","pcmpeqw","pcmpeqd","emms",
	"packsswb","packuswb","punpckhbw","punpckhwd","punpckhdq","packssdw","pand","pandn","por","pxor","pmaddwd",
	"rcpps","rcpss",
	"rsqrtss","movsxd",
	"shufps","shufpd",
	"sqrtpd","sqrtps","sqrtsd","sqrtss",
	"subpd","subps","subsd","subss",
	"ucomisd","ucomiss",
	"unpckhpd","unpckhps",
	"unpcklpd","unpcklps",
	"xorpd","xorps",

	"bt","bts","btr","btc","xlat","cpuid","rsm","bsf","bsr","cmpxchg","cmpxchg8b",
	"hlt","cmc",
	"lgdt","sgdt","lidt","sidt","smsw","lmsw","invlpg",
	"lar","lsl","clts","invd","wbinvd","ud2","wrmsr","rdtsc","rdmsr","rdpmc",
	"fcom","fdivr",
	"fiadd","fimul","ficom","ficomp","fidiv","fidivr",
	"faddp","fmulp","fsubp","fsubrp","fdivp","fdivrp",
	"fbld","fbstp",

	"ffree","frstor","fsave","fucom","fucomp",

	"fldenv","fstenvm",
	"fxch","fabs","fxam",
	"fld1","fldl2t","fldl2e","fldpi","fldlg2","fldln2",

	"fldz","fyl2x","fptan","fpatan","fxtract","fprem1","fdecstp","fincstp",
	"fprem","fyl2xp1","fsincos","frndint","fscale","fsin","fcos","ftst",

	"fstenv","f2xm1","fnop","finit","fclex","fcompp",

	"sysenter","sysexit","sldt","str","lldt","ltr","verr","verw",
	"sfence","lfence","mfence","prefetchnta","prefetcht0","prefetcht1","prefetcht2","prefetch","prefetchw",
	"fxrstor","fxsave","ldmxcsr","stmxcsr",

	"fcmovb", "fcmove", "fcmovbe", "fcmovu", "fcmovnb", "fcmovne", "fcmovnbe", "fcmovnu",
	"fucomi","fcomi",
	"fucomip","fcomip","fucompp",
	"vmcall", "vmlaunch", "vmresume", "vmxoff", "monitor", "mwait", "xgetbv", "xsetbv", "vmrun", "vmmcall",
	"vmload", "vmsave", "stgi", "clgi", "skinit", "invlpga", "swapgs", "rdtscp", "syscall", "sysret", "femms", "getsec",
	"pshufb", "phaddw", "phaddd", "phaddsw", "pmaddubsw", "phsubw", "phsubd", "phsubsw", "psignb", "psignw", "psignd", "pmulhrsw",
	"pabsb", "pabsw", "pabsd", "movbe", "palignr", "rsqrtps", "vmread", "vmwrite", "svldt", "rsldt", "svts", "rsts",
	"xsave", "xrstor", "vmptrld", "vmptrst", "maskmovq", "fnstenv", "fnstcw", "fstp1", "fneni", "fndisi", "fnclex", "fninit", 
	"fsetpm", "fisttp", "fnsave", "fnstsw", "fxch4", "fcomp5", "ffreep", "fxch7", "fstp8", "fstp9", "haddpd", "hsubpd",
	"addsubpd", "addsubps", "movntdq", "fcom2", "fcomp3", "haddps", "hsubps", "movddup", "movsldup", "cvtsi2sd", "cvtsi2ss",
	"movntsd", "movntss", "lddqu", "movshdup", "popcnt", "tzcnt", "lzcnt",
	"pblendvb", "pblendps", "pblendpd", "pblendw", "ptest", "pmovsxbw", "pmovsxbd", "pmovsxbq", "pmovsxwd", "pmovsxwq", "pmovsxdq", "pmuldq",
	"pcmpeqq", "movntdqa", "xsaveopt", "maskmovdqu", "ud1", "pcmpgtq", 
	"aesdec", "aesdeclast", "aesenc", "aesenclast", "aesimc", "aeskeygenassist",
	"rdrand", "rdseed",
	"pmovzxbw", "pmovzxbd", "pmovzxbq", "pmovzxwd", "pmovzxwq", "pmovzxdq",

	"fnmadd132sd", "fnmadd213sd", "fnmadd231sd",
	"fnmadd132ss", "fnmadd213ss", "fnmadd231ss",

	"uleb","sleb","dc",
	"broadcastss", "broadcastsd", "broadcastf128", "perm2f128", "permilpd", "permilps", "roundpd", "roundps", "crc32", "pextrb", "pextrd", "pextrq", "zeroupper",
	"zeroall", "blendpd", "blendps", "blendvpd", "blendvps", "dpps", "extractf128", "insertf128", "maskmovpd", "maskmovps",
	"testps", "testpd", "pcmpistri"
};

enum IntelFlags : uint16_t {
	fl_C = 0x0001,
	fl_P = 0x0004,
	fl_A = 0x0010,
	fl_Z = 0x0040,
	fl_S = 0x0080,
	fl_T = 0x0100,
	fl_I = 0x0200,
	fl_D = 0x0400,
	fl_O = 0x0800,
	fl_OS = fl_S | fl_O
};

enum IntelRegistr : uint8_t {
	regEAX,
	regECX,
	regEDX,
	regEBX,
	regESP,
	regEBP,
	regESI,
	regEDI,
	regR8,
	regR9,
	regR10,
	regR11,
	regR12,
	regR13,
	regR14,
	regR15,
	regEIP
};

enum IntelSegment : uint8_t {
	segES,
	segCS,
	segSS,
	segDS,
	segFS,
	segGS,
	segDefault = 0xff
};

enum IntelRexFlags : uint8_t {
	rexB = 0x01,
	rexX = 0x02,
	rexR = 0x04,
	rexW = 0x08,
	vexL = 0x80
};

#endif // INTEL_COMMAND_TYPE_H
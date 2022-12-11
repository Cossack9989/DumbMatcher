import idc
import idaapi
import idautils
import ida_nalt
import ida_funcs
import ida_hexrays

import os
import json
import ssdeep
import xxhash
import hashlib

from base64 import b64encode


bad_prefixes = ["sub_", "unknow", "nullsub"]


class feature_collection_visitor_t(ida_hexrays.ctree_visitor_t):
    def __init__(self, body_item):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.body_item = body_item

    def visit_expr(self, expr: ida_hexrays.cexpr_t):
        if expr.op == ida_hexrays.cot_obj and (expr.ea & 0xffffffff) != 0xffffffff:
            const = getBytesConst(expr.obj_ea)
            for segm_name in executable_segments_list:
                if const is not None and segments[segm_name]["head"] <= expr.ea < segments[segm_name]["tail"]:
                    if expr.ea not in consts_tbl.keys():
                        consts_tbl[expr.ea] = []
                    consts_tbl[expr.ea].append(b64encode(const).decode('latin-1'))
        elif expr.op == ida_hexrays.cot_obj and (expr.ea & 0xffffffff) == 0xffffffff:
            ea = self.body_item.find_parent_of(expr).ea
            if expr.obj_ea in names.keys():
                symbol_tbl[ea] = names[expr.obj_ea]
        elif expr.op == ida_hexrays.cot_num:
            if expr.ea not in consts_tbl.keys():
                consts_tbl[expr.ea] = []
            consts_tbl[expr.ea].append(expr.numval())
        elif expr.op == ida_hexrays.cot_call and (expr.ea & 0xffffffff) != 0xffffffff:
            calls_vec.append(expr.ea)
            for arg in expr.a:
                if arg.op == ida_hexrays.cot_num:
                    if expr.ea not in consts_tbl.keys():
                        consts_tbl[expr.ea] = []
                    consts_tbl[expr.ea].append(arg.numval())

        return 0

    def scan(self):
        self.apply_to(self.body_item, None)


def getToken():
    _bin = ida_nalt.get_input_file_path()
    _bin_data = open(_bin, "rb").read()
    return hashlib.sha256(_bin_data).hexdigest()[:8]


def getBytesConst(ea):
    if segments[".rodata"]["head"] <= ea < segments[".rodata"]["tail"] \
            or segments[".data"]["head"] <= ea < segments[".data"]["tail"]:
        bytes_const = idc.get_strlit_contents(ea)
        if bytes_const[0] == 0x00:
            return None
        return bytes_const
    return None


def initBaseInfo():
    global collection_attributes_tbl
    collection_attributes_tbl["metapc"] = {
        "flags-jumps": [
            "jc", "jnc", "jz", "jnz", "js", "jns", "jo", "jno",
            "jp", "jnp", "jpe", "jpo", "jcxz", "jecxz", "jrcxz",
            "jmp"
        ],
        "equaled-jumps": [
            "je", "jne", "jz", "jnz",
        ],
        "signed-jumps": [
            "jg", "jl", "jnge", "jnle", "jge", "jle", "jng", "jnl"
        ],
        "unsigned-jumps": [
            "ja", "jb", "jnae", "jnbe", "jae", "jbe", "jna", "jnb"
        ],
        "arithmetic": [
            "add", "adc", "inc", "aaa", "daa",
            "sub", "sbb", "dec", "aas", "das",
            "neg",
            "mul", "imul", "aam",
            "div", "idiv", "aad"
        ],
        "logic": [
            "and", "andn", "andnpd", "andpd", "andps", "andnps",
            "not", "test", "pslld",
            "or", "xor", "xorpd",
        ],
        "shift": [
            "sal", "shl", "sar", "shr", "rol", "ror", "rcl", "rcr",
        ],
        "system": [
            "int", "syscall", "into", "iret", "hlt",
        ],
        "ret": [
            "ret", "retn"
        ]
    }
    collection_attributes_tbl["ARM"] = {
        "flags-jumps": [
            "BVS", "BVC", "BCS", "BCC", "BPL", "BMI", "BAL", "BNV",
            "B",
        ],
        "equaled-jumps": [
            "BEQ", "BNE",
        ],
        "signed-jumps": [
            "BLT", "BLE", "BGT", "BGE",
        ],
        "unsigned-jumps": [
            "BHI", "BLS", "BHS", "BLO",
        ],
        "arithmetic": [
            "ADC", "ADD", "MOV", "RSB", "RSC", "SBC", "SUB", "MLA", "MUL",
        ],
        "logic": [
            "AND", "BIC", "EOR", "ORR", "MVN", "TST",
        ],
        "shift": [
            "LSL", "ASL", "LSR", "ASR", "ROR", "RRX",
        ],
        "system": [
            "SVC", "IRQ", "FIQ", "ABT",
        ],
        "ret": [
            "POP", "BX",
        ]
    }
    collection_attributes_tbl["mipsl"] = collection_attributes_tbl["mipsb"] = {
        "flags-jumps": [
            "beqz", "bnez", "bgtz", "bltz",
            "jr", "j", "b", "bal"
        ],
        "equaled-jumps": [
            "beq", "bne"
        ],
        "signed-jumps": [
            "bgt", "blt", "bge", "ble"
        ],
        "unsigned-jumps": [
            "bgeu", "bleu", "bgtu", "bltu"
        ],
        "arithmetic": [
            'add', 'addu', 'addi', 'addiu',
            'sub', 'subu', 'subi', 'subiu',
            'mul', 'mulu', 'mult', 'multu',
            'div', 'divu'
        ],
        "logic": [
            'and', 'andi',
            'or', 'ori',
            'xor', 'xori',
            'nor',
            'slt', 'slti', 'sltu', 'sltiu', 'sltui',
        ],
        "shift": [
            'sll', 'srl', 'sra', 'sllv', 'srlv', 'srav',
        ],
        "system": [
            'trap', 'eret', 'syscall'
        ],
        "ret": [
            "jr",
        ]
    }
    # https://docs.oracle.com/cd/E19120-01/open.solaris/816-1681/sparcv9-30990/index.html
    collection_attributes_tbl["sparcb"] = {
        "calls": [
            "call"
        ],
        "flags-jumps": [
            "ba", "bn", "bpos", "bneg",
            "bvc", "bvs", "brz", "brlez", "brlz", "brnz", "brgz", "brgez",
        ],
        "equaled-jumps": [
            "be", "bne"
        ],
        "signed-jumps": [
            "ble", "bge", "bl",
        ],
        "unsigned-jumps": [
            "bleu", "bcc", "bcs",
        ],
        # https://docs.oracle.com/cd/E19120-01/open.solaris/816-1681/instructionset-32172/index.html
        "arithmetic": [
            "add", "addcc", "addx", "addxcc",
            "sub", "subcc", "subx", "subxcc",
            "smul", "smulcc", "umul", "umulcc",
            "sdiv", "sdivcc", "udiv", "udivcc",
        ],
        "logic": [
            "and", "andcc", "andn", "andncc",
            "or", "orcc", "orn", "orncc",
            "xnor", "xnorcc", "xor", "xorcc",
        ],
        "shift": [
            "sll", "srl", "sra", "sla", "slln", "srln", "sran", "slan",
        ],
        "system": [
            "rett",
            "tn", "tne", "tnz",
            "te", "tg", "tle", "tge", "tl", "tgu", "tz",
            "tleu", "tcc",
            "tlu", "tgeu", "tpos", "tneg",
            "tvc", "tvs", "ta", "t",
        ],
        "ret": [
            "ret", "restore", "retl",
        ]
    }
    # https://chortle.ccsu.edu/assemblytutorial/Chapter-24/ass24_4.html
    collection_attributes_tbl["PPCL"] = collection_attributes_tbl["PPC"] = {
        "calls": [
            "bl", "bla",
        ],
        "flags-jumps": [
            "b", "ba", "bc", "bca", "bcctr",
        ],
        "equaled-jumps": [
            "beq", "bne",
        ],
        "signed-jumps": [
            "blt", "bgt", "ble", "bge",
        ],
        "unsigned-jumps": [
            "bgeu", "bleu", "bgtu", "bltu",
        ],
        "arithmetic": [
            "add", "addi", "addis", "addic", "addo",
            "adde", "addeo", "addc", "addco", "addf", "addfo", "addze", "addzeo", "addme", "addmeo",
            "sub", "subi", "subis", "subic", "subo",
            "sube", "subeo", "subc", "subco",
            "subf", "subfo", "subze", "subzeo", "subme", "submeo",
            "subfc", "subfco", "subfe", "subfeo", "subfi", "subfis", "subfic", "subfme", "subfmeo", "subfze", "subfzeo",
            "divd", "divdo", "divdu", "divduo",
            "divw", "divwo", "divwu", "divwuo",
            "mulhd", "mulhdo", "mulld", "mulldo", "mulli",
            "mulhw", "mulhwo", "mullw", "mullwo",
        ],
        "logic": [
            "eqv",
            "and", "andi", "andis", "andc",
            "nand", "nor",
            "or", "ori", "oris", "orc",
            "xor", "xori", "xoris",
        ],
        "shift": [
            "rldc", "rldcl", "rldcr",
            "rldicl", "rldicr", "rldimi",
            "rlwimi", "rlwinm", "rlwnm",
            "sld", "slw", "srad", "sradi",
            "sraw", "srawi", "srd", "srw"
        ],
        "system": [
            "sc", "rfi"
        ],
        "ret": [
            "blr"
        ]
    }
    # http://riscvbook.com/chinese/RISC-V-Reader-Chinese-v2p1.pdf
    collection_attributes_tbl["riscv"] = {
        "calls": [
            "jal", "call", "jalr"
        ],
        "flags-jumps": [
            "beqz", "bnez", "bgtz", "bltz",
            "jr", "j", "b", "bal"
        ],
        "equaled-jumps": [
            "beq", "bne"
        ],
        "signed-jumps": [
            "bgt", "blt", "bge", "ble"
        ],
        "unsigned-jumps": [
            "bgeu", "bleu", "bgtu", "bltu"
        ],
        "arithmetic": [
            "add", "addi", "addw", "addiw",
            "sub", "subw"
        ],
        "logic": [
            "xor", "xori", "or", "ori",
            "and", "andi",
            'slt', 'slti', 'sltu', 'sltiu', 'sltui'
        ],
        "shift": [
            "sll", "slli", "srl", "srli",
            "sra", "srai",
            "sllw", "slliw", "srlw", "srliw",
            "sraw", "sraiw"
        ],
        "system": [
            "mret", "sret", "wfi", "ecall", "ebreak"
        ],
        "ret": [
            "ret"
        ]
    }
    # https://blog.csdn.net/doudoudouzoule/article/details/79609630
    collection_attributes_tbl["XTENSA"] = {
        "calls": [
            "call8", "callx8", "callx4", "jx"
        ],
        "flags-jumps": [
            "beqz", "beqz.n", "bnez", "bnez.n", "bgez", "bgez.n", "bltz", "bltz.n",
            "bbc", "bbci", "bbs", "bbsi", "ball", "bnall", "bany", "bnone",
            "j"
        ],
        "equaled-jumps": [
            "beq", "beqi", "bne", "bnei",
        ],
        "signed-jumps": [
            "blt", "bge", "blti", "bgei",
        ],
        "unsigned-jumps": [
            "bltu", "bgeu", "bltui", "bgeui",
        ],
        "arithmetic": [
            "add", "addx2", "addx4", "addx8", "addi", "addmi", "add.n", "addi.n",
            "sub", "subx2", "subx4", "subx8", "subi", "submi", "sub.n", "subi.n",
            "mull", "mul16u", "muluh", "mulsh", "quos", "quou", "rems", "remu",
            "neg", "abs",
        ],
        "logic": [
            "and", "or", "xor"
        ],
        "shift": [
            "extui", "slli", "srli", "srai",
            "src", "sra", "sll", "srl", "ssr", "ssl",
            "ssa8b", "ssa8l", "ssai",
        ],
        "ret": [
            "ret", "retw", "retw.n"
        ]
    }
    collection_attributes_tbl["arcv2"] = {
        "calls": [
            "bl", "bl_s", "bl.d", "blcc", "blcc.d",
        ],
        "flags-jumps": [
            "bcc", "bcc.d", "b", "b_s"
        ],
        "equaled-jumps": [
            "beq", "beq_s", "bne", "bne_s",
            "breq", "breq_s", "brne", "brne_s",
            "beq.d", "bne.d",
            "breq.d", "brne.d",
        ],
        "signed-jumps": [
            "blo", "bls", "bhi", "bhs",
            "brlo", "brls", "brhi", "brhs",
            "blo_s", "bls_s", "bhi_s", "bhs_s",
            "brlo_s", "brls_s", "brhi_s", "brhs_s",
            "blo.d", "bls.d", "bhi.d", "bhs.d",
            "brlo.d", "brls.d", "brhi.d", "brhs.d",
        ],
        "unsigned-jumps": [
            "bgt", "bge", "blt", "ble",
            "brgt", "brge", "brlt", "brle",
            "bgt_s", "bge_s", "blt_s", "ble_s",
            "brgt_s", "brge_s", "brlt_s", "brle_s",
            "bgt.d", "bge.d", "blt.d", "ble.d",
            "brgt.d", "brge.d", "brlt.d", "brle.d",
        ],
        "arithmetic": [
            "add", "add_s", "add1", "add2", "add3", "add.c", "add.f", "add.p", "adc",
            "add.nz", "add.nc", "add.hi", "add.gt", "add.eq", "add.ls", "add.lt",
            "sub", "sub_s", "sub1", "sub2", "sub3", "sub.c", "sub.f", "sub.p", "sbc",
            "sub.nz", "sub.nc", "sub.hi", "sub.gt", "sub.eq", "sub.ls", "sub.lt",
            "rsub", "rsub_s", "rsub1", "rsub2", "rsub3", "rsub.c", "rsub.f", "rsub.p",
            "rsub.nz", "rsub.nc", "rsub.hi", "rsub.gt", "rsub.eq", "rsub.ls", "rsub.lt",
            "mul64", "mulu64", "mpy", "mpyh", "mpyhu", "mpyu",
            "divaw"
        ],
        "logic": [
            "bset", "bset_s", "bset.c", "bset.f", "bset.p", "bset.ne", "bset.eq", "bset.nc", "bset.nz", "bset.hi",
            "bset.gt", "bset.ls", "bset.lt",
            "bclr", "bclr_s", "bclr.c", "bclr.f", "bclr.p", "bclr.ne", "bclr.eq", "bclr.nc", "bclr.nz", "bclr.hi",
            "bclr.gt", "bclr.ls", "bclr.lt",
            "bxor", "bxor_s", "bxor.c", "bxor.f", "bxor.p", "bxor.ne", "bxor.eq", "bxor.nc", "bxor.nz", "bxor.hi",
            "bxor.gt", "bxor.ls", "bxor.lt",
            "bmsk", "bmsk_s", "bmsk.c", "bmsk.f", "bmsk.p", "bmsk.ne", "bmsk.eq", "bmsk.nc", "bmsk.nz", "bmsk.hi",
            "bmsk.gt", "bmsk.ls", "bmsk.lt",
            "bmskn", "bmskn_s", "bmskn.c", "bmskn.f", "bmskn.p", "bmskn.ne", "bmskn.eq", "bmskn.nc", "bmskn.nz",
            "bmskn.hi", "bmskn.gt", "bmskn.ls", "bmskn.lt",
            "neg", "neg_s", "neg.c", "neg.f", "neg.p", "neg.ne", "neg.eq", "neg.nc", "neg.nz", "neg.hi", "neg.gt",
            "neg.ls", "neg.lt",
            "and", "and_s", "and.c", "and.f", "and.p", "and.ne", "and.eq", "and.nc", "and.nz", "and.hi", "and.gt",
            "and.ls", "and.lt",
            "or", "or_s", "or.c", "or.f", "or.p", "or.ne", "or.eq", "or.nc", "or.nz", "or.hi", "or.gt", "or.ls",
            "or.lt",
            "xor", "xor_s", "xor.c", "xor.f", "xor.p", "xor.ne", "xor.eq", "xor.nc", "xor.nz", "xor.hi", "xor.gt",
            "xor.ls", "xor.lt",
            "bic", "bic_s", "bic.c", "bic.f", "bic.p", "bic.ne", "bic.eq", "bic.nc", "bic.nz", "bic.hi", "bic.gt",
            "bic.ls", "bic.lt",
        ],
        "shift": [
            "asl", "asl_s", "asl.c", "asl.f", "asl.p", "asl.ne", "asl.eq", "asl.nc", "asl.nz", "asl.hi", "asl.gt",
            "asl.ls", "asl.lt",
            "asr", "asr_s", "asr.c", "asr.f", "asr.p", "asr.ne", "asr.eq", "asr.nc", "asr.nz", "asr.hi", "asr.gt",
            "asr.ls", "asr.lt",
            "lsr", "lsr_s", "lsr.c", "lsr.f", "lsr.p", "lsr.ne", "lsr.eq", "lsr.nc", "lsr.nz", "lsr.hi", "lsr.gt",
            "lsr.ls", "lsr.lt",
            "rol", "rol_s", "rol.c", "rol.f", "rol.p", "rol.ne", "rol.eq", "rol.nc", "rol.nz", "rol.hi", "rol.gt",
            "rol.ls", "rol.lt",
            "ror", "ror_s", "ror.c", "ror.f", "ror.p", "ror.ne", "ror.eq", "ror.nc", "ror.nz", "ror.hi", "ror.gt",
            "ror.ls", "ror.lt",
            "rlc", "rlc_s", "rlc.c", "rlc.f", "rlc.p", "rlc.ne", "rlc.eq", "rlc.nc", "rlc.nz", "rlc.hi", "rlc.gt",
            "rlc.ls", "rlc.lt",
            "rrc", "rrc_s", "rrc.c", "rrc.f", "rrc.p", "rrc.ne", "rrc.eq", "rrc.nc", "rrc.nz", "rrc.hi", "rrc.gt",
            "rrc.ls", "rrc.lt",
        ],
        "system": [
            "rtie",
            "swi", "swi_s",
            "trap", "trap_s",
        ],
        "ret": [
            "leave_s", "j_s"
        ]
    }
    # https://en.wikibooks.org/wiki/360_Assembly/360_Instructions
    collection_attributes_tbl["s390x"] = {
        "calls": [
            "brasl", "basr", "bal",
            "bz", "bl", "bm", "bh", "bp", "bo",
            "bnz", "bnl", "bnm", "bnh", "bnp", "bno",
            "brz", "brl", "brm", "brh", "brp", "bro",
            "brnz", "brnl", "brnm", "brnh", "brnp", "brno",
            "bsm", "bassm", "bsg", "brc", "brnop", "bru", "brul",
        ],
        "flags-jumps": [
            "j",
            "jo", "jh", "jp", "jl", "jm", "jz", "ju",
            "jno", "jnh", "jnp", "jnl", "jnm", "jnz", "jnu",
            "jlo", "jlh", "jlp", "jll", "jlm", "jlz", "jlu",
            "jlno", "jlnh", "jlnp", "jlnl", "jlnm", "jlnz", "jlnu",
            "jct", "jctg", "jcl", "jlnop",
        ],
        "equaled-jumps": [
            "be", "bne",
            "bre", "brne",
            "je", "jne",
            "jleq", "jlne"
        ],
        "signed-jumps": [],
        "unsigned-jumps": [],
        "arithmetic": [
            'vas', 'vss', 'vms', 'vaer', 'vser', 'vmer', 'vadr', 'vsdr', 'vmdr', 'vddr', 'var', 'vsr', 'vmr', 'vaeq',
            'vseq', 'vmeq', 'vdeq', 'vadq', 'vsdq', 'vmdq', 'vddq', 'vaq', 'vsq', 'vmq', 'mxd', 'sxr', 'axr', 'her',
            'mxdr', 'mxr', 'hdr', 'lcr', 'ae', 'se', 'mde', 'me', 'de', 'au', 'su', 'ad', 'sd', 'md', 'dd', 'aw', 'sw',
            'a', 's', 'm', 'd', 'al', 'sl', 'ah', 'sh', 'mh', 'aer', 'ser', 'mer', 'der', 'aur', 'sur', 'adr', 'sdr',
            'mdr', 'ddr', 'awr', 'swr', 'ar', 'sr', 'mr', 'dr', 'alr', 'slr', 'ahi', 'aghi', 'mhi', 'mghi', 'mad',
            'sqdr', 'sqer', 'mxdbr', 'aebr', 'sebr', 'mdebr', 'debr', 'maebr', 'msebr', 'sqebr', 'sqdbr', 'sqxbr',
            'meebr', 'adbr', 'sdbr', 'mdbr', 'ddbr', 'madbr', 'msdbr', 'maer', 'mser', 'sqxr', 'meer', 'maylr', 'mylr',
            'mayr', 'myr', 'mayhr', 'myhr', 'madr', 'msdr', 'axbr', 'sxbr', 'mxbr', 'dxbr', 'diebr', 'didbr', 'mdtr',
            'mdtra', 'ddtr', 'adtr', 'adtra', 'sdtr', 'sdtra', 'mxtr', 'mxtra', 'dxtr', 'axtr', 'axtra', 'sxtr',
            'sxtra', 'agr', 'sgr', 'algr', 'slgr', 'msgr', 'dsgr', 'agfr', 'sgfr', 'algfr', 'slgfr', 'msgfr', 'dsgfr',
            'mlgr', 'dlgr', 'alcgr', 'slbgr', 'mlr', 'dlr', 'alcr', 'slbr', 'ahhhr', 'shhhr', 'alhhhr', 'slhhhr',
            'ahhlr', 'shhlr', 'alhhlr', 'slhhlr', 'agrk', 'sgrk', 'algrk', 'slgrk', 'mgrk', 'msgrkc', 'ark', 'srk',
            'alrk', 'slrk', 'msrkc', 'msgfi', 'msfi', 'slgfi', 'slfi', 'agfi', 'afi', 'algfi', 'alfi', 'aih', 'alsih',
            'ag', 'sg', 'alg', 'slg', 'msg', 'dsg', 'agf', 'sgf', 'algf', 'slgf', 'msgf', 'dsgf', 'msy', 'ay', 'sy',
            'mfy', 'aly', 'sly', 'ahy', 'shy', 'mhy', 'mlg', 'dlg', 'alcg', 'slbg', 'ml', 'dl', 'alc', 'slb', 'vcvb',
            'vcvbg', 'vcvd', 'vcvdg', 'vpsop', 'vap', 'vsp', 'vmp', 'vmsp', 'vdp', 'vrp', 'vsdp', 'vctz', 'vclz',
            'vseg', 'vsum', 'vsumg', 'vcksm', 'vsumq', 'vfms', 'vfma', 'vpk', 'vpkls', 'vpks', 'vfnms', 'vfnma', 'vmlh',
            'vml', 'vmh', 'vmle', 'vmlo', 'vme', 'vmo', 'vmalh', 'vmal', 'vmah', 'vmale', 'vmalo', 'vmae', 'vmao',
            'vgfm', 'vmsl', 'vaccc', 'vac', 'vgfma', 'vsbcbi', 'vsbi', 'vfpso', 'vfsq', 'vupll', 'vuplh', 'vupl',
            'vuph', 'vfs', 'vfa', 'vfd', 'vfm', 'vavgl', 'vacc', 'vavg', 'va', 'vscbi', 'vs', 'asi', 'alsi', 'agsi',
            'algsi', 'mxdb', 'aeb', 'seb', 'mdeb', 'deb', 'maeb', 'mseb', 'sqeb', 'sqdb', 'meeb', 'adb', 'sdb', 'mdb',
            'ddb', 'madb', 'msdb', 'lde', 'lxd', 'lxe', 'mae', 'mse', 'sqe', 'sqd', 'mee', 'mayl', 'myl', 'may', 'my',
            'mayh', 'myh', 'mad', 'msd', 'pack', 'unpk', 'zap', 'ap', 'sp', 'mp', 'dp'
        ],
        "logic": [
            'x', 'xr', 'xgr', 'xgrk', 'xrk', 'xihf', 'xilf', 'xy', 'xg', 'xi', 'xc', 'xiy', 'vnx', 'vx', 'vnn', 'o',
            'or', 'oihh', 'oihl', 'oilh', 'oill', 'ogr', 'ogrk', 'ork', 'oihf', 'oilf', 'oy', 'og', 'oi', 'oc', 'oiy',
            'vo', 'vno', 'voc', 'n', 'nr', 'nihh', 'nihl', 'nilh', 'nill', 'ngr', 'ngrk', 'ncgrk', 'nrk', 'ncrk',
            'nihf', 'nilf', 'ny', 'ng', 'ni', 'nc', 'niy', 'vn', 'vnc', 'lang', 'laog', 'laxg', 'laag', 'laalg', 'lan',
            'lao', 'lax', 'laa', 'laal', 'nngrk', 'ocgrk', 'nogrk', 'nxgrk', 'nnrk', 'ocrk', 'nork', 'nxrk',
        ],
        "shift": [
            'vsrl', 'vsll', 'sll', 'srl', 'sra', 'sla', 'srdl', 'sldl', 'srda', 'slda', 'vsrp', 'vesl', 'verll',
            'vesrl', 'vesra', 'veslv', 'verim', 'verllv', 'vsl', 'vslb', 'vsldb', 'vesrlv', 'vesrav', 'vsrl', 'vsrlb',
            'vsra', 'vsrab', 'vbperm', 'vsld', 'vsrd', 'vperm', 'srag', 'slag', 'srlg', 'sllg', 'rllg', 'rll', 'risblg',
            'rnsbg', 'risbg', 'rosbg', 'rxsbg', 'sldt', 'srdt', 'slxt', 'srxt', 'srp'
        ],
        "system": [
            "svc", "trap", "trap2", "trace"
        ],
        "ret": [
            "br", "nopr"
        ]
    }
    # https://www.intel.com/content/dam/support/us/en/programmable/support-resources/bulk-container/pdfs/literature/hb/nios2/n2cpu-nii51017.pdf
    collection_attributes_tbl["nios2"] = {
        "calls": [
            "call", "callr",
        ],
        "flags-jumps": [
            "br", "jmpi",
        ],
        "equaled-jumps": [
            "beq", "bne",
        ],
        "signed-jumps": [
            "bge", "bgt", "ble", "blt",
        ],
        "unsigned-jumps": [
            "bgeu", "bgtu", "bleu", "bltu",
        ],
        "arithmetic": [
            "add", "addi", "sub", "subi",
            "mul", "muli", "mulxss", "mulxsu", "mulxuu",
            "div", "divu",
        ],
        "shift": [
            "rol", "roli", "ror", "rori",
            "sll", "slli", "sra", "srai",
            "srl", "srli",
        ],
        "logic": [
            "and", "andi", "andhi",
            "or", "orhi", "ori",
            "nor", "xor", "xorhi", "xori"
        ],
        "system": [
            "eret", "break", "bret", "trap",
        ],
        "ret": [
            "ret",
        ]
    }
    return idaapi.get_inf_structure().procName, idaapi.get_inf_structure().is_64bit()


def get_filters():
    global collection_attributes_tbl
    arch = idaapi.get_inf_structure().procName
    if arch in collection_attributes_tbl.keys():
        return collection_attributes_tbl[arch]
    else:
        print(f"unsupported architecture {arch}")
        return {}


def get_all_segments(debug=False):

    _segments = {}
    _executable_segments_list = []

    for ea in idautils.Segments():
        segm_name = idc.get_segm_name(ea)
        _segments[segm_name] = {
            "head": idc.get_segm_start(ea),
            "tail": idc.get_segm_end(ea)
        }
        if idc.get_segm_attr(ea, idc.SEGATTR_TYPE) == idc.SEG_CODE:
            _executable_segments_list.append(segm_name)
    if debug:
        for segname in _segments.keys():
            print(segname, hex(_segments[segname]['head']), hex(_segments[segname]['tail']))
    return _segments, _executable_segments_list


def get_all_names(debug=False):
    _names = {}
    [_names.update({
        ea: name
    }) for (ea, name) in idautils.Names()]
    if debug:
        for addr in _names.keys():
            print(f"{addr:#x} : {_names[addr]}")
    return _names


def calc_acfg(func, debug=False, decompilable=True):
    cfg = {}
    bb_hash = {}
    bb_ea = {}
    bb_attrs = {}
    block_list = []
    for block in idaapi.FlowChart(func):
        if func.end_ea >= block.end_ea != block.start_ea >= func.start_ea:
            block_list.append(block)
    for block in block_list:
        cfg[str(block.id)] = []
        for succ in block.succs():
            if succ.start_ea <= func.end_ea and succ.end_ea >= func.start_ea:
                cfg[str(block.id)].append(str(succ.id))
        if debug:
            print(f"[{idc.get_func_name(func.start_ea)}]\t {block.start_ea:#x}-{block.end_ea:#x}")
        bb_hash[block.id] = ssdeep.hash(idc.get_bytes(block.start_ea, block.end_ea - block.start_ea))
        bb_ea[block.id] = (block.start_ea, block.end_ea)
        bb_attrs[block.id] = collect_attributes(block.start_ea, block.end_ea, decompilable=decompilable)
    return {"cfg": cfg, "hash": bb_hash, "ea": bb_ea, "attr": bb_attrs}


def collect_attributes(start_ea, end_ea, decompilable=True):

    if decompilable:
        attributes = {
            "consts": [], "symbol": [],
            "calls": 0, "insts": 0, "insts_list": []
        }
        attributes_dict = get_filters()

        current_ip = start_ea

        while current_ip <= end_ea:
            current_inst = idc.print_insn_mnem(current_ip)
            for filter_key in attributes_dict.keys():
                if current_inst in attributes_dict[filter_key]:
                    if filter_key not in attributes.keys():
                        attributes[filter_key] = 0
                    attributes[filter_key] += 1
                    break
            if current_ip in consts_tbl.keys():
                attributes["consts"] += consts_tbl[current_ip]
            if current_ip in symbol_tbl.keys():
                attributes["symbol"].append(symbol_tbl[current_ip])
            if current_ip in calls_vec:
                attributes["calls"] += 1
            attributes["insts"] += 1
            attributes["insts_list"].append(current_inst)
            current_ip = idc.next_head(current_ip)

        return attributes

    else:
        attributes = {"insts": 0, "insts_list": []}
        attributes_dict = get_filters()

        current_ip = start_ea

        while current_ip <= end_ea:
            current_inst = idc.print_insn_mnem(current_ip)
            for filter_key in attributes_dict.keys():
                if current_inst in attributes_dict[filter_key]:
                    if filter_key not in attributes.keys():
                        attributes[filter_key] = 0
                    attributes[filter_key] += 1
                    break
            attributes["insts"] += 1
            attributes["insts_list"].append(current_inst)
            current_ip = idc.next_head(current_ip)

        return attributes


def checkDir(path: str):
    if not os.path.exists(path):
        os.mkdir(path)
    return os.path.exists(path)


def checkSign(sign, signs):
    for _sign in signs:
        if sign in _sign:
            return True
    return False


def get_functions(debug=False, decompilable=True):

    global workdir

    functions = {}

    for segm_name in executable_segments_list:

        for func_ea in idautils.Functions(segments[segm_name]["head"], segments[segm_name]["tail"]):

            func_name = idc.get_func_name(func_ea)
            flag = False
            for bad_word in bad_words:
                if bad_word in func_name:
                    flag = True
                    break
            if flag:
                continue

            func = ida_funcs.get_func(func_ea)
            func_hash = ssdeep.hash(idc.get_bytes(func.start_ea, func.end_ea - func.start_ea))
            func_sign = xxhash.xxh128(func_hash).hexdigest()
            base_name = os.path.basename(ida_nalt.get_input_file_path()).replace('.', '_').replace('/', '.')
            base_dir = os.path.join(workdir, base_name)
            assert checkDir(base_dir)
            existed_signs = os.listdir(base_dir)
            func_path = os.path.join(base_dir, f"{func_sign}.{func_name}.json")
            if checkSign(func_sign, existed_signs):
                print(f"WTF happened to {func_name}?")
                continue
            functions[func_name] = {"hash": func_hash, "head": func.start_ea, "tail": func.end_ea, "hcfg": {}}
            if decompilable:
                try:
                    body = ida_hexrays.decompile(func_ea).body
                    v = feature_collection_visitor_t(body)
                    v.scan()
                except Exception as e:
                    print(e)
            functions[func_name]["acfg"] = calc_acfg(func, debug=debug, decompilable=decompilable)
            consts_tbl.clear()
            symbol_tbl.clear()
            calls_vec.clear()

            json.dump(
                functions[func_name],
                open(func_path, "w")
            )
    if debug:
        for key in functions.keys():
            print(key, functions[key])
    return functions


def run(debug=False):
    global workdir
    arch, bits = initBaseInfo()
    if arch not in collection_attributes_tbl.keys():
        return
    workdir = os.path.join(workdir, arch)
    assert checkDir(workdir)
    decompilable = True if arch in ["metapc", "ARM", "mipsl"] else False
    functions = get_functions(debug=debug, decompilable=decompilable)
    if debug:
        print(json.dumps(functions, indent=4))


idc.auto_wait()
segments, executable_segments_list = get_all_segments()
names = get_all_names()
bad_words = ["unknow", "nullsub", "__cfi_", "__stack_"]

if "EXTRACT_TO" in os.environ.keys() \
        and isinstance(os.environ["EXTRACT_TO"], str) \
        and os.path.exists(os.environ["EXTRACT_TO"]):
    extract_to = os.environ["EXTRACT_TO"]
else:
    extract_to = "/Users/c0ss4ck/Projects/C0ss4ck/DumbMatcher/rawdata/"
    print(f"EXTRACT_TO is not set")

print(f"EXTRACT_TO is set to {extract_to}")

workdir = extract_to
collection_attributes_tbl = {}

consts_tbl = {}
symbol_tbl = {}
calls_vec = []
run(debug=True)
idc.qexit(0)

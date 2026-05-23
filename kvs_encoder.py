#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Кодировщик инструкций для КВС
Промежуточный модуль для обратной совместимости.
Импортирует всё из fixsize и mutsize, реэкспортирует наружу.
Нового кода не содержит.
"""

import struct
import sys
from kvs_data import INSTRUCTIONS, REGISTERS, get_reg_info

# Импорт из fixsize
from kvs_encoder_fixsize import (
    encode_mov_reg_reg,
    encode_mov_reg8_imm8,
    encode_cmp_reg_reg,
    encode_add_sub_reg_reg,
    encode_muldiv,
    encode_and_or_xor_reg_reg,
    encode_not_neg,
    encode_incdec,
    encode_push_reg,
    encode_pop_reg,
    encode_push_imm,
    encode_shift_rotate,
    encode_syscall,
    encode_int,
    encode_hlt,
    encode_int3,
    encode_nop,
    encode_flag_instruction,
    encode_in,
    encode_out,
    encode_string_instruction,
    encode_cpuid,
    encode_rdtsc,
    encode_xchg,
)

# Импорт из mutsize
from kvs_encoder_mutsize import (
    parse_operand,
    parse_memory_operand,
    encode_mov_reg_mem_absolute,
    encode_mov_mem_reg_absolute,
    encode_mov_reg_mem,
    encode_mov_mem_reg,
    encode_lea_mem,
    encode_mov_reg_imm,
    encode_movzx,
    encode_movsx,
    encode_cmp_reg_imm,
    encode_add_sub_reg_imm,
    encode_jmp_rel32,
    encode_jmp_short,
    encode_jcc_rel32,
    encode_jcc_short,
    encode_call,
    encode_ret,
    encode_loop,
    encode_instruction,
)
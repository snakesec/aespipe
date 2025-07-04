/* aes-armv8sca.S */

/*
 * References:
 *  - https://developer.arm.com/documentation/101028/0012/5--Feature-test-macros
 *  - https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst
 */

#if defined(__ARM_FEATURE_BTI_DEFAULT) && __ARM_FEATURE_BTI_DEFAULT == 1 && !defined(__KERNEL__)
#  define BTI_C hint 34  /* bti c: for calls, IE bl instructions */
#  define GNU_PROPERTY_AARCH64_BTI 1 /* bit 0 GNU Notes is for BTI support */
#else
#  define BTI_C
#  define GNU_PROPERTY_AARCH64_BTI 0
#endif

#if defined(__ARM_FEATURE_PAC_DEFAULT) && !defined(__KERNEL__)
#  if __ARM_FEATURE_PAC_DEFAULT & 1
#    define SIGN_LR hint 25 /* paciasp: sign with the A key */
#    define VERIFY_LR hint 29 /* autiasp: verify with the A key */
#  elif __ARM_FEATURE_PAC_DEFAULT & 2
#    define SIGN_LR hint 27 /* pacibsp: sign with the b key */
#    define VERIFY_LR hint 31 /* autibsp: verify with the b key */
#  endif
#  define GNU_PROPERTY_AARCH64_POINTER_AUTH 2 /* bit 1 GNU Notes is for PAC support */
#else
#  define SIGN_LR BTI_C
#  define VERIFY_LR
#  define GNU_PROPERTY_AARCH64_POINTER_AUTH 0
#endif

/* Add the BTI support to GNU Notes section */
#if GNU_PROPERTY_AARCH64_BTI != 0 || GNU_PROPERTY_AARCH64_POINTER_AUTH != 0
    .pushsection .note.gnu.property, "a"; /* Start a new allocatable section */
    .balign 8; /* align it on a byte boundry */
    .long 4; /* size of "GNU\0" */
    .long 0x10; /* size of descriptor */
    .long 0x5; /* NT_GNU_PROPERTY_TYPE_0 */
    .asciz "GNU";
    .long 0xc0000000; /* GNU_PROPERTY_AARCH64_FEATURE_1_AND */
    .long 4; /* Four bytes of data */
    .long (GNU_PROPERTY_AARCH64_BTI|GNU_PROPERTY_AARCH64_POINTER_AUTH); /* BTI or PAC is enabled */
    .long 0; /* padding for 8 byte alignment */
    .popsection; /* end the section */
#endif

#if defined(__linux__) && defined(__KERNEL__)
# include <linux/linkage.h>
#endif
#if !defined(SYM_FUNC_START)
# define SYM_FUNC_START(name)   .globl name ; .align 4 ; name: ; SIGN_LR
#endif
#if !defined(SYM_FUNC_END)
# define SYM_FUNC_END(name)     .set .L__sym_size_##name, .-name ; .size name, .L__sym_size_##name
#endif


/**************************************************/

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Based on arch/arm/include/asm/assembler.h, arch/arm/mm/proc-macros.S
 *
 * Copyright (C) 1996-2000 Russell King
 * Copyright (C) 2012 ARM Ltd.
 *
 * Modified by Jari Ruusu for loop-AES (by removing unnecessary stuff)
 */

	/*
	 * @dst: destination register (64 bit wide)
	 * @sym: name of the symbol
	 */
	.macro	compat_adr_l, dst, sym
	adrp	\dst, \sym
	add	\dst, \dst, :lo12:\sym
	.endm


/**************************************************/

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Scalar AES core transform
 *
 * Copyright (C) 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * Modified by Jari Ruusu for loop-AES (by removing unnecessary stuff)
 */

	.text

	rk		.req	x0
	out		.req	x1
	in		.req	x2
	rounds		.req	x3
	tt		.req	x2

	.macro		__pair1, sz, op, reg0, reg1, in0, in1e, in1d, shift
	.ifc		\op\shift, b0
	ubfiz		\reg0, \in0, #2, #8
	ubfiz		\reg1, \in1e, #2, #8
	.else
	ubfx		\reg0, \in0, #\shift, #8
	ubfx		\reg1, \in1e, #\shift, #8
	.endif

	/*
	 * AArch64 cannot do byte size indexed loads from a table containing
	 * 32-bit quantities, i.e., 'ldrb w12, [tt, w12, uxtw #2]' is not a
	 * valid instruction. So perform the shift explicitly first for the
	 * high bytes (the low byte is shifted implicitly by using ubfiz rather
	 * than ubfx above)
	 */
	.ifnc		\op, b
	ldr		\reg0, [tt, \reg0, uxtw #2]
	ldr		\reg1, [tt, \reg1, uxtw #2]
	.else
	.if		\shift > 0
	lsl		\reg0, \reg0, #2
	lsl		\reg1, \reg1, #2
	.endif
	ldrb		\reg0, [tt, \reg0, uxtw]
	ldrb		\reg1, [tt, \reg1, uxtw]
	.endif
	.endm

	.macro		__pair0, sz, op, reg0, reg1, in0, in1e, in1d, shift
	ubfx		\reg0, \in0, #\shift, #8
	ubfx		\reg1, \in1d, #\shift, #8
	ldr\op		\reg0, [tt, \reg0, uxtw #\sz]
	ldr\op		\reg1, [tt, \reg1, uxtw #\sz]
	.endm

	.macro		__hround, out0, out1, in0, in1, in2, in3, t0, t1, enc, sz, op
	ldp		\out0, \out1, [rk], #8

	__pair\enc	\sz, \op, w12, w13, \in0, \in1, \in3, 0
	__pair\enc	\sz, \op, w14, w15, \in1, \in2, \in0, 8
	__pair\enc	\sz, \op, w16, w17, \in2, \in3, \in1, 16
	__pair\enc	\sz, \op, \t0, \t1, \in3, \in0, \in2, 24

	eor		\out0, \out0, w12
	eor		\out1, \out1, w13
	eor		\out0, \out0, w14, ror #24
	eor		\out1, \out1, w15, ror #24
	eor		\out0, \out0, w16, ror #16
	eor		\out1, \out1, w17, ror #16
	eor		\out0, \out0, \t0, ror #8
	eor		\out1, \out1, \t1, ror #8
	.endm

	.macro		fround, out0, out1, out2, out3, in0, in1, in2, in3, sz=2, op
	__hround	\out0, \out1, \in0, \in1, \in2, \in3, \out2, \out3, 1, \sz, \op
	__hround	\out2, \out3, \in2, \in3, \in0, \in1, \in1, \in2, 1, \sz, \op
	.endm

	.macro		iround, out0, out1, out2, out3, in0, in1, in2, in3, sz=2, op
	__hround	\out0, \out1, \in0, \in3, \in2, \in1, \out2, \out3, 0, \sz, \op
	__hround	\out2, \out3, \in2, \in1, \in0, \in3, \in1, \in0, 0, \sz, \op
	.endm

	.macro		do_crypt, round, ttab, ltab, bsz
	ldp		w4, w5, [in]
	ldp		w6, w7, [in, #8]
	ldp		w8, w9, [rk], #16
	ldp		w10, w11, [rk, #-8]

	eor		w4, w4, w8
	eor		w5, w5, w9
	eor		w6, w6, w10
	eor		w7, w7, w11

	compat_adr_l	tt, \ttab

	tbnz		rounds, #1, 1f

0:	\round		w8, w9, w10, w11, w4, w5, w6, w7
	\round		w4, w5, w6, w7, w8, w9, w10, w11

1:	subs		rounds, rounds, #4
	\round		w8, w9, w10, w11, w4, w5, w6, w7
	b.ls		3f
2:	\round		w4, w5, w6, w7, w8, w9, w10, w11
	b		0b
3:	compat_adr_l	tt, \ltab
	\round		w4, w5, w6, w7, w8, w9, w10, w11, \bsz, b

	stp		w4, w5, [out]
	stp		w6, w7, [out, #8]
	VERIFY_LR
	ret
	.endm

	.align		5
SYM_FUNC_START(_AES_arm64_encrypt)
	do_crypt	fround, _AES_crypto_ft_tab, _AES_crypto_ft_tab + 1, 2
SYM_FUNC_END(_AES_arm64_encrypt)

	.align		5
SYM_FUNC_START(_AES_arm64_decrypt)
	do_crypt	iround, _AES_crypto_it_tab, _AES_crypto_inv_sbox, 0
SYM_FUNC_END(_AES_arm64_decrypt)


/**************************************************/

//
// Copyright (c) 2001, Dr Brian Gladman <brg@gladman.uk.net>, Worcester, UK.
// All rights reserved.
//
// TERMS
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted subject to the following conditions:
//
//  1. Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in the
//     documentation and/or other materials provided with the distribution.
//
//  3. The copyright holder's name must not be used to endorse or promote
//     any products derived from this software without his specific prior
//     written permission.
//
//  This software is provided 'as is' with no express or implied warranties
//  of correctness or fitness for purpose.

// Modified by Jari Ruusu (Converted syntax to GNU CPP/assembler syntax)

// finite field multiplies by {02}, {04} and {08}

#define f2(x)	((x<<1)^(((x>>7)&1)*0x11b))
#define f4(x)	((x<<2)^(((x>>6)&1)*0x11b)^(((x>>6)&2)*0x11b))
#define f8(x)	((x<<3)^(((x>>5)&1)*0x11b)^(((x>>5)&2)*0x11b)^(((x>>5)&4)*0x11b))

// finite field multiplies required in table generation

#define f3(x)	(f2(x) ^ x)
#define f9(x)	(f8(x) ^ x)
#define fb(x)	(f8(x) ^ f2(x) ^ x)
#define fd(x)	(f8(x) ^ f4(x) ^ x)
#define fe(x)	(f8(x) ^ f4(x) ^ f2(x))

// These defines generate the forward table entries

#define u0(x)	((f3(x) << 24) | (x << 16) | (x << 8) | f2(x))
#define u1(x)	((x << 24) | (x << 16) | (f2(x) << 8) | f3(x))
#define u2(x)	((x << 24) | (f2(x) << 16) | (f3(x) << 8) | x)
#define u3(x)	((f2(x) << 24) | (f3(x) << 16) | (x << 8) | x)

// These defines generate the inverse table entries

#define v0(x)	((fb(x) << 24) | (fd(x) << 16) | (f9(x) << 8) | fe(x))
#define v1(x)	((fd(x) << 24) | (f9(x) << 16) | (fe(x) << 8) | fb(x))
#define v2(x)	((f9(x) << 24) | (fe(x) << 16) | (fb(x) << 8) | fd(x))
#define v3(x)	((fe(x) << 24) | (fb(x) << 16) | (fd(x) << 8) | f9(x))

// These defines generate entries for the last round tables

#define w0(x)	(x)

// S-box data - 256 entries

#define sb_data0(p1,p2) \
	p2	p1(0x63),p1(0x7c),p1(0x77),p1(0x7b),p1(0xf2),p1(0x6b),p1(0x6f),p1(0xc5) ;\
	p2	p1(0x30),p1(0x01),p1(0x67),p1(0x2b),p1(0xfe),p1(0xd7),p1(0xab),p1(0x76) ;\
	p2	p1(0xca),p1(0x82),p1(0xc9),p1(0x7d),p1(0xfa),p1(0x59),p1(0x47),p1(0xf0) ;\
	p2	p1(0xad),p1(0xd4),p1(0xa2),p1(0xaf),p1(0x9c),p1(0xa4),p1(0x72),p1(0xc0)
#define sb_data1(p1,p2) \
	p2	p1(0xb7),p1(0xfd),p1(0x93),p1(0x26),p1(0x36),p1(0x3f),p1(0xf7),p1(0xcc) ;\
	p2	p1(0x34),p1(0xa5),p1(0xe5),p1(0xf1),p1(0x71),p1(0xd8),p1(0x31),p1(0x15) ;\
	p2	p1(0x04),p1(0xc7),p1(0x23),p1(0xc3),p1(0x18),p1(0x96),p1(0x05),p1(0x9a) ;\
	p2	p1(0x07),p1(0x12),p1(0x80),p1(0xe2),p1(0xeb),p1(0x27),p1(0xb2),p1(0x75)
#define sb_data2(p1,p2) \
	p2	p1(0x09),p1(0x83),p1(0x2c),p1(0x1a),p1(0x1b),p1(0x6e),p1(0x5a),p1(0xa0) ;\
	p2	p1(0x52),p1(0x3b),p1(0xd6),p1(0xb3),p1(0x29),p1(0xe3),p1(0x2f),p1(0x84) ;\
	p2	p1(0x53),p1(0xd1),p1(0x00),p1(0xed),p1(0x20),p1(0xfc),p1(0xb1),p1(0x5b) ;\
	p2	p1(0x6a),p1(0xcb),p1(0xbe),p1(0x39),p1(0x4a),p1(0x4c),p1(0x58),p1(0xcf)
#define sb_data3(p1,p2) \
	p2	p1(0xd0),p1(0xef),p1(0xaa),p1(0xfb),p1(0x43),p1(0x4d),p1(0x33),p1(0x85) ;\
	p2	p1(0x45),p1(0xf9),p1(0x02),p1(0x7f),p1(0x50),p1(0x3c),p1(0x9f),p1(0xa8) ;\
	p2	p1(0x51),p1(0xa3),p1(0x40),p1(0x8f),p1(0x92),p1(0x9d),p1(0x38),p1(0xf5) ;\
	p2	p1(0xbc),p1(0xb6),p1(0xda),p1(0x21),p1(0x10),p1(0xff),p1(0xf3),p1(0xd2)
#define sb_data4(p1,p2) \
	p2	p1(0xcd),p1(0x0c),p1(0x13),p1(0xec),p1(0x5f),p1(0x97),p1(0x44),p1(0x17) ;\
	p2	p1(0xc4),p1(0xa7),p1(0x7e),p1(0x3d),p1(0x64),p1(0x5d),p1(0x19),p1(0x73) ;\
	p2	p1(0x60),p1(0x81),p1(0x4f),p1(0xdc),p1(0x22),p1(0x2a),p1(0x90),p1(0x88) ;\
	p2	p1(0x46),p1(0xee),p1(0xb8),p1(0x14),p1(0xde),p1(0x5e),p1(0x0b),p1(0xdb)
#define sb_data5(p1,p2) \
	p2	p1(0xe0),p1(0x32),p1(0x3a),p1(0x0a),p1(0x49),p1(0x06),p1(0x24),p1(0x5c) ;\
	p2	p1(0xc2),p1(0xd3),p1(0xac),p1(0x62),p1(0x91),p1(0x95),p1(0xe4),p1(0x79) ;\
	p2	p1(0xe7),p1(0xc8),p1(0x37),p1(0x6d),p1(0x8d),p1(0xd5),p1(0x4e),p1(0xa9) ;\
	p2	p1(0x6c),p1(0x56),p1(0xf4),p1(0xea),p1(0x65),p1(0x7a),p1(0xae),p1(0x08)
#define sb_data6(p1,p2) \
	p2	p1(0xba),p1(0x78),p1(0x25),p1(0x2e),p1(0x1c),p1(0xa6),p1(0xb4),p1(0xc6) ;\
	p2	p1(0xe8),p1(0xdd),p1(0x74),p1(0x1f),p1(0x4b),p1(0xbd),p1(0x8b),p1(0x8a) ;\
	p2	p1(0x70),p1(0x3e),p1(0xb5),p1(0x66),p1(0x48),p1(0x03),p1(0xf6),p1(0x0e) ;\
	p2	p1(0x61),p1(0x35),p1(0x57),p1(0xb9),p1(0x86),p1(0xc1),p1(0x1d),p1(0x9e)
#define sb_data7(p1,p2) \
	p2	p1(0xe1),p1(0xf8),p1(0x98),p1(0x11),p1(0x69),p1(0xd9),p1(0x8e),p1(0x94) ;\
	p2	p1(0x9b),p1(0x1e),p1(0x87),p1(0xe9),p1(0xce),p1(0x55),p1(0x28),p1(0xdf) ;\
	p2	p1(0x8c),p1(0xa1),p1(0x89),p1(0x0d),p1(0xbf),p1(0xe6),p1(0x42),p1(0x68) ;\
	p2	p1(0x41),p1(0x99),p1(0x2d),p1(0x0f),p1(0xb0),p1(0x54),p1(0xbb),p1(0x16)

// Inverse S-box data - 256 entries

#define ib_data0(p1,p2) \
	p2	p1(0x52),p1(0x09),p1(0x6a),p1(0xd5),p1(0x30),p1(0x36),p1(0xa5),p1(0x38) ;\
	p2	p1(0xbf),p1(0x40),p1(0xa3),p1(0x9e),p1(0x81),p1(0xf3),p1(0xd7),p1(0xfb) ;\
	p2	p1(0x7c),p1(0xe3),p1(0x39),p1(0x82),p1(0x9b),p1(0x2f),p1(0xff),p1(0x87) ;\
	p2	p1(0x34),p1(0x8e),p1(0x43),p1(0x44),p1(0xc4),p1(0xde),p1(0xe9),p1(0xcb)
#define ib_data1(p1,p2) \
	p2	p1(0x54),p1(0x7b),p1(0x94),p1(0x32),p1(0xa6),p1(0xc2),p1(0x23),p1(0x3d) ;\
	p2	p1(0xee),p1(0x4c),p1(0x95),p1(0x0b),p1(0x42),p1(0xfa),p1(0xc3),p1(0x4e) ;\
	p2	p1(0x08),p1(0x2e),p1(0xa1),p1(0x66),p1(0x28),p1(0xd9),p1(0x24),p1(0xb2) ;\
	p2	p1(0x76),p1(0x5b),p1(0xa2),p1(0x49),p1(0x6d),p1(0x8b),p1(0xd1),p1(0x25)
#define ib_data2(p1,p2) \
	p2	p1(0x72),p1(0xf8),p1(0xf6),p1(0x64),p1(0x86),p1(0x68),p1(0x98),p1(0x16) ;\
	p2	p1(0xd4),p1(0xa4),p1(0x5c),p1(0xcc),p1(0x5d),p1(0x65),p1(0xb6),p1(0x92) ;\
	p2	p1(0x6c),p1(0x70),p1(0x48),p1(0x50),p1(0xfd),p1(0xed),p1(0xb9),p1(0xda) ;\
	p2	p1(0x5e),p1(0x15),p1(0x46),p1(0x57),p1(0xa7),p1(0x8d),p1(0x9d),p1(0x84)
#define ib_data3(p1,p2) \
	p2	p1(0x90),p1(0xd8),p1(0xab),p1(0x00),p1(0x8c),p1(0xbc),p1(0xd3),p1(0x0a) ;\
	p2	p1(0xf7),p1(0xe4),p1(0x58),p1(0x05),p1(0xb8),p1(0xb3),p1(0x45),p1(0x06) ;\
	p2	p1(0xd0),p1(0x2c),p1(0x1e),p1(0x8f),p1(0xca),p1(0x3f),p1(0x0f),p1(0x02) ;\
	p2	p1(0xc1),p1(0xaf),p1(0xbd),p1(0x03),p1(0x01),p1(0x13),p1(0x8a),p1(0x6b)
#define ib_data4(p1,p2) \
	p2	p1(0x3a),p1(0x91),p1(0x11),p1(0x41),p1(0x4f),p1(0x67),p1(0xdc),p1(0xea) ;\
	p2	p1(0x97),p1(0xf2),p1(0xcf),p1(0xce),p1(0xf0),p1(0xb4),p1(0xe6),p1(0x73) ;\
	p2	p1(0x96),p1(0xac),p1(0x74),p1(0x22),p1(0xe7),p1(0xad),p1(0x35),p1(0x85) ;\
	p2	p1(0xe2),p1(0xf9),p1(0x37),p1(0xe8),p1(0x1c),p1(0x75),p1(0xdf),p1(0x6e)
#define ib_data5(p1,p2) \
	p2	p1(0x47),p1(0xf1),p1(0x1a),p1(0x71),p1(0x1d),p1(0x29),p1(0xc5),p1(0x89) ;\
	p2	p1(0x6f),p1(0xb7),p1(0x62),p1(0x0e),p1(0xaa),p1(0x18),p1(0xbe),p1(0x1b) ;\
	p2	p1(0xfc),p1(0x56),p1(0x3e),p1(0x4b),p1(0xc6),p1(0xd2),p1(0x79),p1(0x20) ;\
	p2	p1(0x9a),p1(0xdb),p1(0xc0),p1(0xfe),p1(0x78),p1(0xcd),p1(0x5a),p1(0xf4)
#define ib_data6(p1,p2) \
	p2	p1(0x1f),p1(0xdd),p1(0xa8),p1(0x33),p1(0x88),p1(0x07),p1(0xc7),p1(0x31) ;\
	p2	p1(0xb1),p1(0x12),p1(0x10),p1(0x59),p1(0x27),p1(0x80),p1(0xec),p1(0x5f) ;\
	p2	p1(0x60),p1(0x51),p1(0x7f),p1(0xa9),p1(0x19),p1(0xb5),p1(0x4a),p1(0x0d) ;\
	p2	p1(0x2d),p1(0xe5),p1(0x7a),p1(0x9f),p1(0x93),p1(0xc9),p1(0x9c),p1(0xef)
#define ib_data7(p1,p2) \
	p2	p1(0xa0),p1(0xe0),p1(0x3b),p1(0x4d),p1(0xae),p1(0x2a),p1(0xf5),p1(0xb0) ;\
	p2	p1(0xc8),p1(0xeb),p1(0xbb),p1(0x3c),p1(0x83),p1(0x53),p1(0x99),p1(0x61) ;\
	p2	p1(0x17),p1(0x2b),p1(0x04),p1(0x7e),p1(0xba),p1(0x77),p1(0xd6),p1(0x26) ;\
	p2	p1(0xe1),p1(0x69),p1(0x14),p1(0x63),p1(0x55),p1(0x21),p1(0x0c),p1(0x7d)

	.section .rodata

// The forward xor tables

	.align	6
_AES_crypto_ft_tab:
	sb_data0(u0, .long)
	sb_data1(u0, .long)
	sb_data2(u0, .long)
	sb_data3(u0, .long)
	sb_data4(u0, .long)
	sb_data5(u0, .long)
	sb_data6(u0, .long)
	sb_data7(u0, .long)

	sb_data0(u1, .long)
	sb_data1(u1, .long)
	sb_data2(u1, .long)
	sb_data3(u1, .long)
	sb_data4(u1, .long)
	sb_data5(u1, .long)
	sb_data6(u1, .long)
	sb_data7(u1, .long)

	sb_data0(u2, .long)
	sb_data1(u2, .long)
	sb_data2(u2, .long)
	sb_data3(u2, .long)
	sb_data4(u2, .long)
	sb_data5(u2, .long)
	sb_data6(u2, .long)
	sb_data7(u2, .long)

	sb_data0(u3, .long)
	sb_data1(u3, .long)
	sb_data2(u3, .long)
	sb_data3(u3, .long)
	sb_data4(u3, .long)
	sb_data5(u3, .long)
	sb_data6(u3, .long)
	sb_data7(u3, .long)

// The inverse xor tables

	.align	6
_AES_crypto_it_tab:
	ib_data0(v0, .long)
	ib_data1(v0, .long)
	ib_data2(v0, .long)
	ib_data3(v0, .long)
	ib_data4(v0, .long)
	ib_data5(v0, .long)
	ib_data6(v0, .long)
	ib_data7(v0, .long)

	ib_data0(v1, .long)
	ib_data1(v1, .long)
	ib_data2(v1, .long)
	ib_data3(v1, .long)
	ib_data4(v1, .long)
	ib_data5(v1, .long)
	ib_data6(v1, .long)
	ib_data7(v1, .long)

	ib_data0(v2, .long)
	ib_data1(v2, .long)
	ib_data2(v2, .long)
	ib_data3(v2, .long)
	ib_data4(v2, .long)
	ib_data5(v2, .long)
	ib_data6(v2, .long)
	ib_data7(v2, .long)

	ib_data0(v3, .long)
	ib_data1(v3, .long)
	ib_data2(v3, .long)
	ib_data3(v3, .long)
	ib_data4(v3, .long)
	ib_data5(v3, .long)
	ib_data6(v3, .long)
	ib_data7(v3, .long)

	.align	6
_AES_crypto_inv_sbox:
	ib_data0(w0, .byte)
	ib_data1(w0, .byte)
	ib_data2(w0, .byte)
	ib_data3(w0, .byte)
	ib_data4(w0, .byte)
	ib_data5(w0, .byte)
	ib_data6(w0, .byte)
	ib_data7(w0, .byte)

	.section	.note.GNU-stack,"",@progbits

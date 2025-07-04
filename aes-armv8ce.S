/* aes-armv8ce.S */

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
 * linux/arch/arm64/crypto/aes-ce.S - AES cipher for ARMv8 with
 *                                    Crypto Extensions
 *
 * Copyright (C) 2013 - 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * Modified by Jari Ruusu for loop-AES (by removing unnecessary stuff)
 */

	.arch		armv8-a+crypto

	xtsmask		.req	v16
	cbciv		.req	v16
	vctr		.req	v16

	/* preload all round keys */
	.macro		load_round_keys, rounds, rk
	cmp		\rounds, #12
	blo		2222f		/* 128 bits */
	beq		1111f		/* 192 bits */
	ld1		{v17.4s-v18.4s}, [\rk], #32
1111:	ld1		{v19.4s-v20.4s}, [\rk], #32
2222:	ld1		{v21.4s-v24.4s}, [\rk], #64
	ld1		{v25.4s-v28.4s}, [\rk], #64
	ld1		{v29.4s-v31.4s}, [\rk]
	.endm

	/* prepare for encryption with key in rk[] */
	.macro		enc_prepare, rounds, rk, temp
	mov		\temp, \rk
	load_round_keys	\rounds, \temp
	.endm

	/* prepare for decryption with key in rk[] */
	.macro		dec_prepare, rounds, rk, temp
	mov		\temp, \rk
	load_round_keys	\rounds, \temp
	.endm

	.macro		do_enc_Nx, de, mc, k, i0, i1, i2, i3, i4
	aes\de		\i0\().16b, \k\().16b
	aes\mc		\i0\().16b, \i0\().16b
	.ifnb		\i1
	aes\de		\i1\().16b, \k\().16b
	aes\mc		\i1\().16b, \i1\().16b
	.ifnb		\i3
	aes\de		\i2\().16b, \k\().16b
	aes\mc		\i2\().16b, \i2\().16b
	aes\de		\i3\().16b, \k\().16b
	aes\mc		\i3\().16b, \i3\().16b
	.ifnb		\i4
	aes\de		\i4\().16b, \k\().16b
	aes\mc		\i4\().16b, \i4\().16b
	.endif
	.endif
	.endif
	.endm

	/* up to 5 interleaved encryption rounds with the same round key */
	.macro		round_Nx, enc, k, i0, i1, i2, i3, i4
	.ifc		\enc, e
	do_enc_Nx	e, mc, \k, \i0, \i1, \i2, \i3, \i4
	.else
	do_enc_Nx	d, imc, \k, \i0, \i1, \i2, \i3, \i4
	.endif
	.endm

	/* up to 5 interleaved final rounds */
	.macro		fin_round_Nx, de, k, k2, i0, i1, i2, i3, i4
	aes\de		\i0\().16b, \k\().16b
	.ifnb		\i1
	aes\de		\i1\().16b, \k\().16b
	.ifnb		\i3
	aes\de		\i2\().16b, \k\().16b
	aes\de		\i3\().16b, \k\().16b
	.ifnb		\i4
	aes\de		\i4\().16b, \k\().16b
	.endif
	.endif
	.endif
	eor		\i0\().16b, \i0\().16b, \k2\().16b
	.ifnb		\i1
	eor		\i1\().16b, \i1\().16b, \k2\().16b
	.ifnb		\i3
	eor		\i2\().16b, \i2\().16b, \k2\().16b
	eor		\i3\().16b, \i3\().16b, \k2\().16b
	.ifnb		\i4
	eor		\i4\().16b, \i4\().16b, \k2\().16b
	.endif
	.endif
	.endif
	.endm

	/* up to 5 interleaved blocks */
	.macro		do_block_Nx, enc, rounds, i0, i1, i2, i3, i4
	cmp		\rounds, #12
	blo		2222f		/* 128 bits */
	beq		1111f		/* 192 bits */
	round_Nx	\enc, v17, \i0, \i1, \i2, \i3, \i4
	round_Nx	\enc, v18, \i0, \i1, \i2, \i3, \i4
1111:	round_Nx	\enc, v19, \i0, \i1, \i2, \i3, \i4
	round_Nx	\enc, v20, \i0, \i1, \i2, \i3, \i4
2222:	.irp		key, v21, v22, v23, v24, v25, v26, v27, v28, v29
	round_Nx	\enc, \key, \i0, \i1, \i2, \i3, \i4
	.endr
	fin_round_Nx	\enc, v30, v31, \i0, \i1, \i2, \i3, \i4
	.endm

	.macro		encrypt_block, in, rounds, t0, t1, t2
	do_block_Nx	e, \rounds, \in
	.endm

	.macro		decrypt_block, in, rounds, t0, t1, t2
	do_block_Nx	d, \rounds, \in
	.endm

	.macro		decrypt_block5x, i0, i1, i2, i3, i4, rounds, t0, t1, t2
	do_block_Nx	d, \rounds, \i0, \i1, \i2, \i3, \i4
	.endm


/**************************************************/

/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * linux/arch/arm64/crypto/aes-modes.S - chaining mode wrappers for AES
 *
 * Copyright (C) 2013 - 2017 Linaro Ltd <ard.biesheuvel@linaro.org>
 *
 * Modified by Jari Ruusu for loop-AES (by removing unnecessary stuff)
 */

	.text
	.align		4

#define MAX_STRIDE	5

SYM_FUNC_START(_ARM_CE_aes_decrypt_block5x)
	decrypt_block5x	v0, v1, v2, v3, v4, w3, x2, x8, w7
	VERIFY_LR
	ret
SYM_FUNC_END(_ARM_CE_aes_decrypt_block5x)

	/*
	 * aes_cbc_encrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks, u8 iv[])
	 * aes_cbc_decrypt(u8 out[], u8 const in[], u8 const rk[], int rounds,
	 *		   int blocks, u8 iv[])
	 */

SYM_FUNC_START(_ARM_CE_aes_cbc_encrypt)
	ld1		{v4.16b}, [x5]			/* get iv */
	enc_prepare	w3, x2, x6

.Lcbcencloop4x:
	subs		w4, w4, #4
	bmi		.Lcbcenc1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 pt blocks */
	eor		v0.16b, v0.16b, v4.16b		/* ..and xor with iv */
	encrypt_block	v0, w3, x2, x6, w7
	eor		v1.16b, v1.16b, v0.16b
	encrypt_block	v1, w3, x2, x6, w7
	eor		v2.16b, v2.16b, v1.16b
	encrypt_block	v2, w3, x2, x6, w7
	eor		v3.16b, v3.16b, v2.16b
	encrypt_block	v3, w3, x2, x6, w7
	st1		{v0.16b-v3.16b}, [x0], #64
	mov		v4.16b, v3.16b
	b		.Lcbcencloop4x
.Lcbcenc1x:
	adds		w4, w4, #4
	beq		.Lcbcencout
.Lcbcencloop:
	ld1		{v0.16b}, [x1], #16		/* get next pt block */
	eor		v4.16b, v4.16b, v0.16b		/* ..and xor with iv */
	encrypt_block	v4, w3, x2, x6, w7
	st1		{v4.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lcbcencloop
.Lcbcencout:
	st1		{v4.16b}, [x5]			/* return iv */
	VERIFY_LR
	ret
SYM_FUNC_END(_ARM_CE_aes_cbc_encrypt)

SYM_FUNC_START(_ARM_CE_aes_cbc_decrypt)
	stp		x29, x30, [sp, #-16]!
	mov		x29, sp

	ld1		{cbciv.16b}, [x5]		/* get iv */
.Lessivcbcdecstart:
	dec_prepare	w3, x2, x6

.LcbcdecloopNx:
	subs		w4, w4, #MAX_STRIDE
	bmi		.Lcbcdec1x
	ld1		{v0.16b-v3.16b}, [x1], #64	/* get 4 ct blocks */
	ld1		{v4.16b}, [x1], #16		/* get 1 ct block */
	mov		v5.16b, v0.16b
	mov		v6.16b, v1.16b
	mov		v7.16b, v2.16b
	bl		_ARM_CE_aes_decrypt_block5x
	sub		x1, x1, #32
	eor		v0.16b, v0.16b, cbciv.16b
	eor		v1.16b, v1.16b, v5.16b
	ld1		{v5.16b}, [x1], #16		/* reload 1 ct block */
	ld1		{cbciv.16b}, [x1], #16		/* reload 1 ct block */
	eor		v2.16b, v2.16b, v6.16b
	eor		v3.16b, v3.16b, v7.16b
	eor		v4.16b, v4.16b, v5.16b
	st1		{v0.16b-v3.16b}, [x0], #64
	st1		{v4.16b}, [x0], #16
	b		.LcbcdecloopNx
.Lcbcdec1x:
	adds		w4, w4, #MAX_STRIDE
	beq		.Lcbcdecout
.Lcbcdecloop:
	ld1		{v1.16b}, [x1], #16		/* get next ct block */
	mov		v0.16b, v1.16b			/* ...and copy to v0 */
	decrypt_block	v0, w3, x2, x6, w7
	eor		v0.16b, v0.16b, cbciv.16b	/* xor with iv => pt */
	mov		cbciv.16b, v1.16b		/* ct is next iv */
	st1		{v0.16b}, [x0], #16
	subs		w4, w4, #1
	bne		.Lcbcdecloop
.Lcbcdecout:
	st1		{cbciv.16b}, [x5]		/* return iv */
	ldp		x29, x30, [sp], #16
	VERIFY_LR
	ret
SYM_FUNC_END(_ARM_CE_aes_cbc_decrypt)

	.section	.note.GNU-stack,"",@progbits

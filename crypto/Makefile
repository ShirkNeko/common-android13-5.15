# SPDX-License-Identifier: GPL-2.0
#
# Cryptographic API
#

obj-$(CONFIG_CRYPTO) += crypto.o
crypto-y := api.o cipher.o compress.o

obj-$(CONFIG_CRYPTO_ENGINE) += crypto_engine.o
obj-$(CONFIG_CRYPTO_FIPS) += fips.o

crypto_algapi-$(CONFIG_PROC_FS) += proc.o
crypto_algapi-y := algapi.o scatterwalk.o $(crypto_algapi-y)
obj-$(CONFIG_CRYPTO_ALGAPI2) += crypto_algapi.o

obj-$(CONFIG_CRYPTO_AEAD2) += aead.o
obj-$(CONFIG_CRYPTO_AEAD2) += geniv.o

obj-$(CONFIG_CRYPTO_SKCIPHER2) += skcipher.o
obj-$(CONFIG_CRYPTO_SEQIV) += seqiv.o
obj-$(CONFIG_CRYPTO_ECHAINIV) += echainiv.o

crypto_hash-y += ahash.o
crypto_hash-y += shash.o
obj-$(CONFIG_CRYPTO_HASH2) += crypto_hash.o

obj-$(CONFIG_CRYPTO_AKCIPHER2) += akcipher.o
obj-$(CONFIG_CRYPTO_KPP2) += kpp.o

dh_generic-y := dh.o
dh_generic-y += dh_helper.o
obj-$(CONFIG_CRYPTO_DH) += dh_generic.o

$(obj)/rsapubkey.asn1.o: $(obj)/rsapubkey.asn1.c $(obj)/rsapubkey.asn1.h
$(obj)/rsaprivkey.asn1.o: $(obj)/rsaprivkey.asn1.c $(obj)/rsaprivkey.asn1.h
$(obj)/rsa_helper.o: $(obj)/rsapubkey.asn1.h $(obj)/rsaprivkey.asn1.h

rsa_generic-y := rsapubkey.asn1.o
rsa_generic-y += rsaprivkey.asn1.o
rsa_generic-y += rsa.o
rsa_generic-y += rsa_helper.o
rsa_generic-y += rsa-pkcs1pad.o
obj-$(CONFIG_CRYPTO_RSA) += rsa_generic.o

$(obj)/sm2signature.asn1.o: $(obj)/sm2signature.asn1.c $(obj)/sm2signature.asn1.h
$(obj)/sm2.o: $(obj)/sm2signature.asn1.h

sm2_generic-y += sm2signature.asn1.o
sm2_generic-y += sm2.o

obj-$(CONFIG_CRYPTO_SM2) += sm2_generic.o

$(obj)/ecdsasignature.asn1.o: $(obj)/ecdsasignature.asn1.c $(obj)/ecdsasignature.asn1.h
$(obj)/ecdsa.o: $(obj)/ecdsasignature.asn1.h
ecdsa_generic-y += ecdsa.o
ecdsa_generic-y += ecdsasignature.asn1.o
obj-$(CONFIG_CRYPTO_ECDSA) += ecdsa_generic.o

crypto_acompress-y := acompress.o
crypto_acompress-y += scompress.o
obj-$(CONFIG_CRYPTO_ACOMP2) += crypto_acompress.o

cryptomgr-y := algboss.o testmgr.o

obj-$(CONFIG_CRYPTO_MANAGER2) += cryptomgr.o
obj-$(CONFIG_CRYPTO_USER) += crypto_user.o
crypto_user-y := crypto_user_base.o
crypto_user-$(CONFIG_CRYPTO_STATS) += crypto_user_stat.o
obj-$(CONFIG_CRYPTO_CMAC) += cmac.o
obj-$(CONFIG_CRYPTO_HMAC) += hmac.o
obj-$(CONFIG_CRYPTO_VMAC) += vmac.o
obj-$(CONFIG_CRYPTO_XCBC) += xcbc.o
obj-$(CONFIG_CRYPTO_NULL2) += crypto_null.o
obj-$(CONFIG_CRYPTO_MD4) += md4.o
obj-$(CONFIG_CRYPTO_MD5) += md5.o
obj-$(CONFIG_CRYPTO_RMD160) += rmd160.o
obj-$(CONFIG_CRYPTO_SHA1) += sha1_generic.o
obj-$(CONFIG_CRYPTO_SHA256) += sha256_generic.o
obj-$(CONFIG_CRYPTO_SHA512) += sha512_generic.o
obj-$(CONFIG_CRYPTO_SHA3) += sha3_generic.o
obj-$(CONFIG_CRYPTO_SM3) += sm3_generic.o
obj-$(CONFIG_CRYPTO_STREEBOG) += streebog_generic.o
obj-$(CONFIG_CRYPTO_WP512) += wp512.o
CFLAGS_wp512.o := $(call cc-option,-fno-schedule-insns)  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=79149
obj-$(CONFIG_CRYPTO_BLAKE2B) += blake2b_generic.o
obj-$(CONFIG_CRYPTO_GF128MUL) += gf128mul.o
obj-$(CONFIG_CRYPTO_ECB) += ecb.o
obj-$(CONFIG_CRYPTO_CBC) += cbc.o
obj-$(CONFIG_CRYPTO_CFB) += cfb.o
obj-$(CONFIG_CRYPTO_PCBC) += pcbc.o
obj-$(CONFIG_CRYPTO_CTS) += cts.o
obj-$(CONFIG_CRYPTO_LRW) += lrw.o
obj-$(CONFIG_CRYPTO_XTS) += xts.o
obj-$(CONFIG_CRYPTO_CTR) += ctr.o
obj-$(CONFIG_CRYPTO_XCTR) += xctr.o
obj-$(CONFIG_CRYPTO_HCTR2) += hctr2.o
obj-$(CONFIG_CRYPTO_KEYWRAP) += keywrap.o
obj-$(CONFIG_CRYPTO_ADIANTUM) += adiantum.o
obj-$(CONFIG_CRYPTO_NHPOLY1305) += nhpoly1305.o
obj-$(CONFIG_CRYPTO_GCM) += gcm.o
obj-$(CONFIG_CRYPTO_CCM) += ccm.o
obj-$(CONFIG_CRYPTO_CHACHA20POLY1305) += chacha20poly1305.o
obj-$(CONFIG_CRYPTO_AEGIS128) += aegis128.o
aegis128-y := aegis128-core.o

ifeq ($(ARCH),arm)
CFLAGS_aegis128-neon-inner.o += -ffreestanding -march=armv8-a -mfloat-abi=softfp
CFLAGS_aegis128-neon-inner.o += -mfpu=crypto-neon-fp-armv8
aegis128-$(CONFIG_CRYPTO_AEGIS128_SIMD) += aegis128-neon.o aegis128-neon-inner.o
endif
ifeq ($(ARCH),arm64)
aegis128-cflags-y := -ffreestanding -mcpu=generic+crypto
aegis128-cflags-$(CONFIG_CC_IS_GCC) += -ffixed-q16 -ffixed-q17 -ffixed-q18 \
				       -ffixed-q19 -ffixed-q20 -ffixed-q21 \
				       -ffixed-q22 -ffixed-q23 -ffixed-q24 \
				       -ffixed-q25 -ffixed-q26 -ffixed-q27 \
				       -ffixed-q28 -ffixed-q29 -ffixed-q30 \
				       -ffixed-q31
CFLAGS_aegis128-neon-inner.o += $(aegis128-cflags-y)
CFLAGS_REMOVE_aegis128-neon-inner.o += -mgeneral-regs-only
aegis128-$(CONFIG_CRYPTO_AEGIS128_SIMD) += aegis128-neon.o aegis128-neon-inner.o
endif

obj-$(CONFIG_CRYPTO_PCRYPT) += pcrypt.o
obj-$(CONFIG_CRYPTO_CRYPTD) += cryptd.o
obj-$(CONFIG_CRYPTO_DES) += des_generic.o
obj-$(CONFIG_CRYPTO_FCRYPT) += fcrypt.o
obj-$(CONFIG_CRYPTO_BLOWFISH) += blowfish_generic.o
obj-$(CONFIG_CRYPTO_BLOWFISH_COMMON) += blowfish_common.o
obj-$(CONFIG_CRYPTO_TWOFISH) += twofish_generic.o
obj-$(CONFIG_CRYPTO_TWOFISH_COMMON) += twofish_common.o
obj-$(CONFIG_CRYPTO_SERPENT) += serpent_generic.o
CFLAGS_serpent_generic.o := $(call cc-option,-fsched-pressure)  # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=79149
obj-$(CONFIG_CRYPTO_AES) += aes_generic.o
CFLAGS_aes_generic.o := $(call cc-option,-fno-code-hoisting) # https://gcc.gnu.org/bugzilla/show_bug.cgi?id=83356
obj-$(CONFIG_CRYPTO_SM4) += sm4_generic.o
obj-$(CONFIG_CRYPTO_AES_TI) += aes_ti.o
obj-$(CONFIG_CRYPTO_CAMELLIA) += camellia_generic.o
obj-$(CONFIG_CRYPTO_CAST_COMMON) += cast_common.o
obj-$(CONFIG_CRYPTO_CAST5) += cast5_generic.o
obj-$(CONFIG_CRYPTO_CAST6) += cast6_generic.o
obj-$(CONFIG_CRYPTO_ARC4) += arc4.o
obj-$(CONFIG_CRYPTO_TEA) += tea.o
obj-$(CONFIG_CRYPTO_KHAZAD) += khazad.o
obj-$(CONFIG_CRYPTO_ANUBIS) += anubis.o
obj-$(CONFIG_CRYPTO_SEED) += seed.o
obj-$(CONFIG_CRYPTO_CHACHA20) += chacha_generic.o
obj-$(CONFIG_CRYPTO_POLY1305) += poly1305_generic.o
obj-$(CONFIG_CRYPTO_DEFLATE) += deflate.o
obj-$(CONFIG_CRYPTO_MICHAEL_MIC) += michael_mic.o
obj-$(CONFIG_CRYPTO_CRC32C) += crc32c_generic.o
obj-$(CONFIG_CRYPTO_CRC32) += crc32_generic.o
obj-$(CONFIG_CRYPTO_CRCT10DIF) += crct10dif_common.o crct10dif_generic.o
obj-$(CONFIG_CRYPTO_AUTHENC) += authenc.o authencesn.o
obj-$(CONFIG_CRYPTO_LZO) += lzo.o lzo-rle.o
obj-$(CONFIG_CRYPTO_LZ4) += lz4.o
obj-$(CONFIG_CRYPTO_LZ4K) += lz4k.o
obj-$(CONFIG_CRYPTO_LZ4HC) += lz4hc.o
obj-$(CONFIG_CRYPTO_LZ4KD) += lz4kd.o
obj-$(CONFIG_CRYPTO_XXHASH) += xxhash_generic.o
obj-$(CONFIG_CRYPTO_842) += 842.o
obj-$(CONFIG_CRYPTO_RNG2) += rng.o
obj-$(CONFIG_CRYPTO_ANSI_CPRNG) += ansi_cprng.o
obj-$(CONFIG_CRYPTO_DRBG) += drbg.o
obj-$(CONFIG_CRYPTO_JITTERENTROPY) += jitterentropy_rng.o
CFLAGS_jitterentropy.o = -O0
KASAN_SANITIZE_jitterentropy.o = n
UBSAN_SANITIZE_jitterentropy.o = n
jitterentropy_rng-y := jitterentropy.o jitterentropy-kcapi.o
obj-$(CONFIG_CRYPTO_TEST) += tcrypt.o
obj-$(CONFIG_CRYPTO_GHASH) += ghash-generic.o
obj-$(CONFIG_CRYPTO_POLYVAL) += polyval-generic.o
obj-$(CONFIG_CRYPTO_USER_API) += af_alg.o
obj-$(CONFIG_CRYPTO_USER_API_HASH) += algif_hash.o
obj-$(CONFIG_CRYPTO_USER_API_SKCIPHER) += algif_skcipher.o
obj-$(CONFIG_CRYPTO_USER_API_RNG) += algif_rng.o
obj-$(CONFIG_CRYPTO_USER_API_AEAD) += algif_aead.o
obj-$(CONFIG_CRYPTO_ZSTD) += zstd.o
obj-$(CONFIG_CRYPTO_OFB) += ofb.o
obj-$(CONFIG_CRYPTO_ECC) += ecc.o
obj-$(CONFIG_CRYPTO_ESSIV) += essiv.o
obj-$(CONFIG_CRYPTO_CURVE25519) += curve25519-generic.o

ecdh_generic-y += ecdh.o
ecdh_generic-y += ecdh_helper.o
obj-$(CONFIG_CRYPTO_ECDH) += ecdh_generic.o

$(obj)/ecrdsa_params.asn1.o: $(obj)/ecrdsa_params.asn1.c $(obj)/ecrdsa_params.asn1.h
$(obj)/ecrdsa_pub_key.asn1.o: $(obj)/ecrdsa_pub_key.asn1.c $(obj)/ecrdsa_pub_key.asn1.h
$(obj)/ecrdsa.o: $(obj)/ecrdsa_params.asn1.h $(obj)/ecrdsa_pub_key.asn1.h
ecrdsa_generic-y += ecrdsa.o
ecrdsa_generic-y += ecrdsa_params.asn1.o
ecrdsa_generic-y += ecrdsa_pub_key.asn1.o
obj-$(CONFIG_CRYPTO_ECRDSA) += ecrdsa_generic.o

#
# generic algorithms and the async_tx api
#
obj-$(CONFIG_XOR_BLOCKS) += xor.o
obj-$(CONFIG_ASYNC_CORE) += async_tx/
obj-$(CONFIG_ASYMMETRIC_KEY_TYPE) += asymmetric_keys/
obj-$(CONFIG_CRYPTO_HASH_INFO) += hash_info.o
crypto_simd-y := simd.o
obj-$(CONFIG_CRYPTO_SIMD) += crypto_simd.o

ifneq ($(CONFIG_CRYPTO_FIPS140_MOD),)

FIPS140_CFLAGS := -D__DISABLE_EXPORTS -DBUILD_FIPS140_KO -include fips140-defs.h

CFLAGS_jitterentropy-fips.o := -O0
KASAN_SANITIZE_jitterentropy-fips.o = n
UBSAN_SANITIZE_jitterentropy-fips.o = n

#
# Create a separate FIPS archive containing a duplicate of each builtin generic
# module that is in scope for FIPS 140-2 certification
#
crypto-fips-objs := drbg.o ecb.o cbc.o ctr.o cts.o gcm.o xts.o hmac.o cmac.o \
		    gf128mul.o aes_generic.o lib-crypto-aes.o \
		    jitterentropy.o jitterentropy-kcapi.o \
		    sha1_generic.o sha256_generic.o sha512_generic.o \
		    lib-memneq.o lib-sha1.o lib-crypto-sha256.o
crypto-fips-objs := $(foreach o,$(crypto-fips-objs),$(o:.o=-fips.o))

# get the arch to add its objects to $(crypto-fips-objs)
include $(srctree)/arch/$(ARCH)/crypto/Kbuild.fips140

extra-$(CONFIG_CRYPTO_FIPS140_MOD) += crypto-fips.a

$(obj)/%-fips.o: KBUILD_CFLAGS += $(FIPS140_CFLAGS)
$(obj)/%-fips.o: $(src)/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-%-fips.o: $(srctree)/lib/%.c FORCE
	$(call if_changed_rule,cc_o_c)
$(obj)/lib-crypto-%-fips.o: $(srctree)/lib/crypto/%.c FORCE
	$(call if_changed_rule,cc_o_c)

$(obj)/crypto-fips.a: $(addprefix $(obj)/,$(crypto-fips-objs)) FORCE
	$(call if_changed,ar_and_symver)

fips140-objs := \
	fips140-alg-registration.o \
	fips140-module.o \
	fips140-refs.o \
	fips140-selftests.o \
	crypto-fips.a
fips140-$(CONFIG_CRYPTO_FIPS140_MOD_EVAL_TESTING) += \
	fips140-eval-testing.o
obj-m += fips140.o

CFLAGS_fips140-alg-registration.o += $(FIPS140_CFLAGS)
CFLAGS_fips140-module.o += $(FIPS140_CFLAGS)
CFLAGS_fips140-selftests.o += $(FIPS140_CFLAGS)
CFLAGS_fips140-eval-testing.o += $(FIPS140_CFLAGS)

hostprogs-always-y := fips140_gen_hmac
HOSTLDLIBS_fips140_gen_hmac := -lcrypto -lelf

endif

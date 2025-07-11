// SPDX-License-Identifier: GPL-2.0-only
/*
 * LZ4 - Fast LZ compression algorithm
 * Copyright (C) 2011 - 2016, Yann Collet.
 * BSD 2 - Clause License (http://www.opensource.org/licenses/bsd - license.php)
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *	* Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *	* Redistributions in binary form must reproduce the above
 * copyright notice, this list of conditions and the following disclaimer
 * in the documentation and/or other materials provided with the
 * distribution.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 * You can contact the author at :
 *	- LZ4 homepage : http://www.lz4.org
 *	- LZ4 source repository : https://github.com/lz4/lz4
 *
 *	Changed for kernel usage by:
 *	Sven Schmidt <4sschmid@informatik.uni-hamburg.de>
 */

/*-************************************
 *	Dependencies
 **************************************/
#include <linux/lz4.h>
#include "lz4pdefs.h"
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>	 /* memset, memcpy */
#include <linux/delay.h>
#include <linux/types.h>
#include <asm/unaligned.h>

#include "lz4p_compress.h"
#include "lz4p_decompress.h"

#define DEBUGLOG(l, ...) {}	/* disabled */

#ifndef assert
#define assert(condition) ((void)0)
#endif

/* lz4p decode function begin */

/*-************************************
 *	Architecture specifics
 **************************************/
#if defined(CONFIG_64BIT)
#define LZ4_ARCH64 1
#else
#define LZ4_ARCH64 0
#endif

#if defined(__LITTLE_ENDIAN)
#define LZ4_LITTLE_ENDIAN 1
#else
#define LZ4_LITTLE_ENDIAN 0
#endif

/*-************************************
 *	Constants
 **************************************/
#define MINMATCH 4

#define WILDCOPYLENGTH 8
#define LASTLITERALS 5
#define MFLIMIT (WILDCOPYLENGTH + MINMATCH)

/*
 * ensure it's possible to write 2 x wildcopyLength
 * without overflowing output buffer
 */
#define MATCH_SAFEGUARD_DISTANCE  ((2 * WILDCOPYLENGTH) - MINMATCH)

#define HASH_UNIT sizeof(size_t)

#define KB (1 << 10)
#define MB (1 << 20)
#define GB (1U << 30)

#define MAXD_LOG 16
#define MAX_DISTANCE ((1 << MAXD_LOG) - 1)

#define ML_BITS	4
#define ML_MASK	((1U << ML_BITS) - 1)
#define RUN_BITS (8 - ML_BITS)
#define RUN_MASK ((1U << RUN_BITS) - 1)

extern int _lz4_decompress_asm(uint8_t **dst_ptr, uint8_t *dst_begin,
				uint8_t *dst_end, const uint8_t **src_ptr,
				const uint8_t *src_end, bool dip);

/*-************************************
 *	Reading and writing into memory
 **************************************/
static FORCE_INLINE U16 LZ4H_readLE16(const void *memPtr)
{
	return get_unaligned_le16(memPtr);
}

static FORCE_INLINE void LZ4H_copy8(void *dst, const void *src)
{
#if LZ4_ARCH64
	U64 a = get_unaligned((const U64 *)src);

	put_unaligned(a, (U64 *)dst);
#else
	U32 a = get_unaligned((const U32 *)src);
	U32 b = get_unaligned((const U32 *)src + 1);

	put_unaligned(a, (U32 *)dst);
	put_unaligned(b, (U32 *)dst + 1);
#endif
}

/*
 * customized variant of memcpy,
 * which can overwrite up to 7 bytes beyond dstEnd
 */
static FORCE_INLINE void LZ4H_wildCopy(void *dstPtr,
	const void *srcPtr, void *dstEnd)
{
	BYTE *d = (BYTE *)dstPtr;
	const BYTE *s = (const BYTE *)srcPtr;
	BYTE *const e = (BYTE *)dstEnd;

	do {
		LZ4H_copy8(d, s);
		d += 8;
		s += 8;
	} while (d < e);
}

#define DEBUGLOG(l, ...) {}	/* disabled */
#define LZ4_STATIC_ASSERT(c)    BUILD_BUG_ON(!(c))

/*
 * no public solution to solve our requirement yet.
 * see: <required buffer size for LZ4_decompress_safe_partial>
 *      https://groups.google.com/forum/#!topic/lz4c/_3kkz5N6n00
 */
static FORCE_INLINE int __lz4_decompress_safe_partial(
	uint8_t         *dst_ptr,
	const uint8_t   *src_ptr,
	BYTE            *dst,
	int             outputSize,
	const void      *src,
	int             inputSize,
	bool            trusted)
{
	/* Local Variables */
	const BYTE *ip = (const BYTE *) src_ptr;
	const BYTE *const iend = src + inputSize;

	BYTE *op = (BYTE *) dst_ptr;
	BYTE *const oend = dst + outputSize;
	BYTE *cpy;

	static const unsigned int inc32table[] = { 0, 1, 2, 1, 0, 4, 4, 4 };
	static const int dec64table[] = { 0, 0, 0, -1, -4, 1, 2, 3 };

	/* Set up the "end" pointers for the shortcut. */
	const BYTE *const shortiend = iend - 14 /*maxLL*/ - 2 /*offset*/;
	const BYTE *const shortoend = oend - 14 /*maxLL*/ - 18 /*maxML*/;

	DEBUGLOG(5, "%s (srcSize:%i, dstSize:%i)", __func__,
		 inputSize, outputSize);

	/* Empty output buffer */
	if (unlikely(!outputSize))
		return ((inputSize == 1) && (*ip == 0)) ? 0 : -EINVAL;

	if (unlikely(!inputSize))
		return -EINVAL;

	/* Main Loop : decode sequences */
	while (1) {
		size_t length;
		const BYTE *match;
		size_t offset;

		/* get literal length */
		unsigned int const token = *ip++;

		length = token >> ML_BITS;

		/* ip < iend before the increment */
		if (ip > iend) {
			pr_err("ip[0x%p] > iend[0x%p] op[0x%p] > oend[0x%p] src[0x%p] dst[0x%p] src_ptr[0x%p] dst_ptr[0x%p] (srcSize:%i, dstSize:%i) length:%zd",
				ip, iend, op, oend, src, dst, src_ptr, dst_ptr, inputSize, outputSize, length);
			return -ENOMEM;
		}

		/*
		 * A two-stage shortcut for the most common case:
		 * 1) If the literal length is 0..14, and there is enough
		 * space, enter the shortcut and copy 16 bytes on behalf
		 * of the literals (in the fast mode, only 8 bytes can be
		 * safely copied this way).
		 * 2) Further if the match length is 4..18, copy 18 bytes
		 * in a similar manner; but we ensure that there's enough
		 * space in the output for those 18 bytes earlier, upon
		 * entering the shortcut (in other words, there is a
		 * combined check for both stages).
		 */
		if (length != RUN_MASK &&
			/*
			 * strictly "less than" on input, to re-enter
			 * the loop with at least one byte
			 */
			likely((ip < shortiend) & (op <= shortoend))) {

			/* Copy the literals */
			memcpy(op, ip, 16);
			op += length;
			ip += length;

			/*
			 * The second stage:
			 * prepare for match copying, decode full info.
			 * If it doesn't work out, the info won't be wasted.
			 */
			length = token & ML_MASK; /* match length */
			offset = LZ4H_readLE16(ip);
			ip += 2;
			match = op - offset;
			//DBG_BUGON(match > op); /* check overflow */

			/* Do not deal with overlapping matches. */
			if ((length != ML_MASK) &&
				(offset >= 8) && (match >= dst)) {
				/* Copy the match. */
				LZ4H_copy8(op + 0, match + 0);
				LZ4H_copy8(op + 8, match + 8);
				memcpy(op + 16, match + 16, 2);
				op += length + MINMATCH;
				/* Both stages worked, load the next token. */
				continue;
			}

			/*
			 * The second stage didn't work out, but the info
			 * is ready. Propel it right to the point of match
			 * copying.
			 */
			goto _copy_match;
		}

		/* decode literal length */
		if (length == RUN_MASK) {
			unsigned int s;

			if (unlikely(!trusted && ip >= iend - RUN_MASK)) {
				/* overflow detection */
				goto _output_error;
			}

			do {
				s = *ip++;
				length += s;
			} while (likely(ip < iend - RUN_MASK) & (s == 255));

			if (!trusted) {
				if (unlikely((uintptr_t)(op) + length < (uintptr_t)op))
					/* overflow detection */
					goto _output_error;
				if (unlikely((uintptr_t)(ip) + length < (uintptr_t)ip))
					/* overflow detection */
					goto _output_error;
			}
		}

		/* copy literals */
		cpy = op + length;
		LZ4_STATIC_ASSERT(MFLIMIT >= WILDCOPYLENGTH);

		if ((cpy > oend - MFLIMIT)
			|| (ip + length > iend - (2 + 1 + LASTLITERALS))) {
			if (cpy > oend) {
				/*
				 * Partial decoding :
				 * stop in the middle of literal segment
				 */
				cpy = oend;
				length = oend - op;
			}

			if (!trusted && ip + length > iend) {
				/*
				 * Error :
				 * read attempt beyond
				 * end of input buffer
				 */
				goto _output_error;
			}

			memcpy(op, ip, length);
			ip += length;
			op += length;

			/* Necessarily EOF, due to parsing restrictions */
			if (cpy == oend)
				break;
		} else {
			/* may overwrite up to WILDCOPYLENGTH beyond cpy */
			LZ4H_wildCopy(op, ip, cpy);
			ip += length;
			op = cpy;
		}

		/* get offset */
		offset = LZ4H_readLE16(ip);
		ip += 2;
		match = op - offset;

		/* get matchlength */
		length = token & ML_MASK;

_copy_match:
		if (length == ML_MASK) {
			unsigned int s;

			do {
				s = *ip++;

				if (!trusted && ip > iend - LASTLITERALS)
					goto _output_error;

				length += s;
			} while (s == 255);

			if (unlikely(!trusted &&
					 (uintptr_t)(op) + length < (uintptr_t)op)) {
				/* overflow detection */
				goto _output_error;
			}
		}

		length += MINMATCH;

		/* copy match within block */
		cpy = op + length;

		/*
		 * partialDecoding :
		 * may not respect endBlock parsing restrictions
		 */
		//DBG_BUGON(op > oend);
		if (cpy > oend - MATCH_SAFEGUARD_DISTANCE) {
			size_t const mlen = min(length, (size_t)(oend - op));
			const BYTE * const matchEnd = match + mlen;
			BYTE * const copyEnd = op + mlen;

			if (matchEnd > op) {
				/* overlap copy */
				while (op < copyEnd)
					*op++ = *match++;
			} else {
				memcpy(op, match, mlen);
			}
			op = copyEnd;
			if (op == oend)
				break;
			continue;
		}

		if (unlikely(offset < 8)) {
			op[0] = match[0];
			op[1] = match[1];
			op[2] = match[2];
			op[3] = match[3];
			match += inc32table[offset];
			memcpy(op + 4, match, 4);
			match -= dec64table[offset];
		} else {
			LZ4H_copy8(op, match);
			match += 8;
		}

		op += 8;
		if (unlikely(cpy > oend - MATCH_SAFEGUARD_DISTANCE)) {
			BYTE * const oCopyLimit = oend - (WILDCOPYLENGTH - 1);

			if (!trusted && cpy > oend - LASTLITERALS) {
				/*
				 * Error : last LASTLITERALS bytes
				 * must be literals (uncompressed)
				 */
				goto _output_error;
			}

			if (op < oCopyLimit) {
				LZ4H_wildCopy(op, match, oCopyLimit);
				match += oCopyLimit - op;
				op = oCopyLimit;
			}
			while (op < cpy)
				*op++ = *match++;
		} else {
			LZ4H_copy8(op, match);
			if (length > 16)
				LZ4H_wildCopy(op + 8, match + 8, cpy);
		}
		op = cpy; /* wildcopy correction */
	}

	/* end of decoding */
	/* Nb of output bytes decoded */
	return (int) (((BYTE *)op) - dst);

	/* Overflow error detected */
_output_error:
	return -ERANGE;
}

static size_t lz4p_decompress(const void *source,
				void *dest,
				size_t inputSize,
				size_t outputSize,
				bool accel, bool dip)
{
	uint8_t *dstPtr = dest;
	const uint8_t *srcPtr = source;
	size_t ret;

	/* Go fast if we can, keeping away from the end of buffers */
	if (outputSize > LZ4_FAST_MARGIN && inputSize > LZ4_FAST_MARGIN &&
		accel && lz4_decompress_accel_enable()) {
		ret = lz4_decompress_asm(&dstPtr, dest,
					dest + outputSize - LZ4_FAST_MARGIN,
					&srcPtr,
					source + inputSize - LZ4_FAST_MARGIN,
					dip);
		if (ret) {
			pr_err("LZ4_ACCELERATOR failed source[%p, %zd] dest[%p, %zd] srcPtr[%p] dstPtr[%p] dip[%u] ret:%zd",
				source, inputSize, dest, outputSize, srcPtr, dstPtr, dip, ret);
			return -1;
		}
	}
	/* Finish in safe */
	return __lz4_decompress_safe_partial(dstPtr, srcPtr, dest, outputSize,
						 source, inputSize, false);
}

/* lz4p decode function end */

/*
 * LZ4_decompress_generic_origin() :
 * This generic decompression function covers all use cases.
 * It shall be instantiated several times, using different sets of directives.
 * Note that it is important for performance that this function really get inlined,
 * in order to remove useless branches during compilation optimization.
 */
static FORCE_INLINE int LZ4_decompress_generic_origin(
	 const char * const src,
	 char * const dst,
	 int srcSize,
		/*
		 * If endOnInput == endOnInputSize,
		 * this value is `dstCapacity`
		 */
	 int outputSize,
	 /* endOnOutputSize, endOnInputSize */
	 enum endCondition_directive endOnInput,
	 /* full, partial */
	 enum earlyEnd_directive partialDecoding,
	 /* noDict, withPrefix64k, usingExtDict */
	 enum dict_directive dict,
	 /* always <= dst, == dst when no prefix */
	 const BYTE * const lowPrefix,
	 /* only if dict == usingExtDict */
	 const BYTE * const dictStart,
	 /* note : = 0 if noDict */
	 const size_t dictSize
	 )
{
	const BYTE *ip = (const BYTE *) src;
	const BYTE * const iend = ip + srcSize;

	BYTE *op = (BYTE *) dst;
	BYTE * const oend = op + outputSize;
	BYTE *cpy;

	const BYTE * const dictEnd = (const BYTE *)dictStart + dictSize;
	static const unsigned int inc32table[8] = {0, 1, 2, 1, 0, 4, 4, 4};
	static const int dec64table[8] = {0, 0, 0, -1, -4, 1, 2, 3};

	const int safeDecode = (endOnInput == endOnInputSize);
	const int checkOffset = ((safeDecode) && (dictSize < (int)(64 * KB)));

	/* Set up the "end" pointers for the shortcut. */
	const BYTE *const shortiend = iend -
		(endOnInput ? 14 : 8) /*maxLL*/ - 2 /*offset*/;
	const BYTE *const shortoend = oend -
		(endOnInput ? 14 : 8) /*maxLL*/ - 18 /*maxML*/;

	DEBUGLOG(5, "%s (srcSize:%i, dstSize:%i)", __func__,
		 srcSize, outputSize);

	/* Special cases */
	assert(lowPrefix <= op);
	assert(src != NULL);

	/* Empty output buffer */
	if ((endOnInput) && (unlikely(outputSize == 0)))
		return ((srcSize == 1) && (*ip == 0)) ? 0 : -1;

	if ((!endOnInput) && (unlikely(outputSize == 0)))
		return (*ip == 0 ? 1 : -1);

	if ((endOnInput) && unlikely(srcSize == 0))
		return -1;

	/* Main Loop : decode sequences */
	while (1) {
		size_t length;
		const BYTE *match;
		size_t offset;

		/* get literal length */
		unsigned int const token = *ip++;

		length = token>>ML_BITS;

		/* ip < iend before the increment */
		assert(!endOnInput || ip <= iend);

		if ((endOnInput ? length != RUN_MASK : length <= 8)
			&& likely((endOnInput ? ip < shortiend : 1) &
				 (op <= shortoend))) {
			/* Copy the literals */
			LZ4_memcpy(op, ip, endOnInput ? 16 : 8);
			op += length; ip += length;

			/*
			 * The second stage:
			 * prepare for match copying, decode full info.
			 * If it doesn't work out, the info won't be wasted.
			 */
			length = token & ML_MASK; /* match length */
			offset = LZ4_readLE16(ip);
			ip += 2;
			match = op - offset;
			assert(match <= op); /* check overflow */

			/* Do not deal with overlapping matches. */
			if ((length != ML_MASK) &&
				(offset >= 8) &&
				(dict == withPrefix64k || match >= lowPrefix)) {
				/* Copy the match. */
				LZ4_memcpy(op + 0, match + 0, 8);
				LZ4_memcpy(op + 8, match + 8, 8);
				LZ4_memcpy(op + 16, match + 16, 2);
				op += length + MINMATCH;
				/* Both stages worked, load the next token. */
				continue;
			}

			/*
			 * The second stage didn't work out, but the info
			 * is ready. Propel it right to the point of match
			 * copying.
			 */
			goto _copy_match;
		}

		/* decode literal length */
		if (length == RUN_MASK) {
			unsigned int s;

			if (unlikely(endOnInput ? ip >= iend - RUN_MASK : 0)) {
				/* overflow detection */
				goto _output_error;
			}
			do {
				s = *ip++;
				length += s;
			} while (likely(endOnInput
				? ip < iend - RUN_MASK
				: 1) & (s == 255));

			if ((safeDecode)
			    && unlikely((uintptr_t)(op) +
					length < (uintptr_t)(op))) {
				/* overflow detection */
				goto _output_error;
			}
			if ((safeDecode)
				&& unlikely((uintptr_t)(ip) +
					length < (uintptr_t)(ip))) {
				/* overflow detection */
				goto _output_error;
			}
		}

		/* copy literals */
		cpy = op + length;
		LZ4_STATIC_ASSERT(MFLIMIT >= WILDCOPYLENGTH);

		if (((endOnInput) && ((cpy > oend - MFLIMIT)
			|| (ip + length > iend - (2 + 1 + LASTLITERALS))))
			|| ((!endOnInput) && (cpy > oend - WILDCOPYLENGTH))) {
			if (partialDecoding) {
				if (cpy > oend) {
					/*
					 * Partial decoding :
					 * stop in the middle of literal segment
					 */
					cpy = oend;
					length = oend - op;
				}
				if ((endOnInput)
					&& (ip + length > iend)) {
					/*
					 * Error :
					 * read attempt beyond
					 * end of input buffer
					 */
					goto _output_error;
				}
			} else {
				if ((!endOnInput)
					&& (cpy != oend)) {
					/*
					 * Error :
					 * block decoding must
					 * stop exactly there
					 */
					goto _output_error;
				}
				if ((endOnInput)
					&& ((ip + length != iend)
					|| (cpy > oend))) {
					/*
					 * Error :
					 * input must be consumed
					 */
					goto _output_error;
				}
			}

			/*
			 * supports overlapping memory regions; only matters
			 * for in-place decompression scenarios
			 */
			LZ4_memmove(op, ip, length);
			ip += length;
			op += length;

			/* Necessarily EOF when !partialDecoding.
			 * When partialDecoding, it is EOF if we've either
			 * filled the output buffer or
			 * can't proceed with reading an offset for following match.
			 */
			if (!partialDecoding || (cpy == oend) || (ip >= (iend - 2)))
				break;
		} else {
			/* may overwrite up to WILDCOPYLENGTH beyond cpy */
			LZ4_wildCopy(op, ip, cpy);
			ip += length;
			op = cpy;
		}

		/* get offset */
		offset = LZ4_readLE16(ip);
		ip += 2;
		match = op - offset;

		/* get matchlength */
		length = token & ML_MASK;

_copy_match:
		if ((checkOffset) && (unlikely(match + dictSize < lowPrefix))) {
			/* Error : offset outside buffers */
			goto _output_error;
		}

		/* costs ~1%; silence an msan warning when offset == 0 */
		/*
		 * note : when partialDecoding, there is no guarantee that
		 * at least 4 bytes remain available in output buffer
		 */
		if (!partialDecoding) {
			assert(oend > op);
			assert(oend - op >= 4);

			LZ4_write32(op, (U32)offset);
		}

		if (length == ML_MASK) {
			unsigned int s;

			do {
				s = *ip++;

				if ((endOnInput) && (ip > iend - LASTLITERALS))
					goto _output_error;

				length += s;
			} while (s == 255);

			if ((safeDecode)
				&& unlikely(
					(uintptr_t)(op) + length < (uintptr_t)op)) {
				/* overflow detection */
				goto _output_error;
			}
		}

		length += MINMATCH;

		/* match starting within external dictionary */
		if ((dict == usingExtDict) && (match < lowPrefix)) {
			if (unlikely(op + length > oend - LASTLITERALS)) {
				/* doesn't respect parsing restriction */
				if (!partialDecoding)
					goto _output_error;
				length = min(length, (size_t)(oend - op));
			}

			if (length <= (size_t)(lowPrefix - match)) {
				/*
				 * match fits entirely within external
				 * dictionary : just copy
				 */
				memmove(op, dictEnd - (lowPrefix - match),
					length);
				op += length;
			} else {
				/*
				 * match stretches into both external
				 * dictionary and current block
				 */
				size_t const copySize = (size_t)(lowPrefix - match);
				size_t const restSize = length - copySize;

				LZ4_memcpy(op, dictEnd - copySize, copySize);
				op += copySize;
				if (restSize > (size_t)(op - lowPrefix)) {
					/* overlap copy */
					BYTE * const endOfMatch = op + restSize;
					const BYTE *copyFrom = lowPrefix;

					while (op < endOfMatch)
						*op++ = *copyFrom++;
				} else {
					LZ4_memcpy(op, lowPrefix, restSize);
					op += restSize;
				}
			}
			continue;
		}

		/* copy match within block */
		cpy = op + length;

		/*
		 * partialDecoding :
		 * may not respect endBlock parsing restrictions
		 */
		assert(op <= oend);
		if (partialDecoding &&
			(cpy > oend - MATCH_SAFEGUARD_DISTANCE)) {
			size_t const mlen = min(length, (size_t)(oend - op));
			const BYTE * const matchEnd = match + mlen;
			BYTE * const copyEnd = op + mlen;

			if (matchEnd > op) {
				/* overlap copy */
				while (op < copyEnd)
					*op++ = *match++;
			} else {
				LZ4_memcpy(op, match, mlen);
			}
			op = copyEnd;
			if (op == oend)
				break;
			continue;
		}

		if (unlikely(offset < 8)) {
			op[0] = match[0];
			op[1] = match[1];
			op[2] = match[2];
			op[3] = match[3];
			match += inc32table[offset];
			LZ4_memcpy(op + 4, match, 4);
			match -= dec64table[offset];
		} else {
			LZ4_copy8(op, match);
			match += 8;
		}

		op += 8;

		if (unlikely(cpy > oend - MATCH_SAFEGUARD_DISTANCE)) {
			BYTE * const oCopyLimit = oend - (WILDCOPYLENGTH - 1);

			if (cpy > oend - LASTLITERALS) {
				/*
				 * Error : last LASTLITERALS bytes
				 * must be literals (uncompressed)
				 */
				goto _output_error;
			}

			if (op < oCopyLimit) {
				LZ4_wildCopy(op, match, oCopyLimit);
				match += oCopyLimit - op;
				op = oCopyLimit;
			}
			while (op < cpy)
				*op++ = *match++;
		} else {
			LZ4_copy8(op, match);
			if (length > 16)
				LZ4_wildCopy(op + 8, match + 8, cpy);
		}
		op = cpy; /* wildcopy correction */
	}

	/* end of decoding */
	if (endOnInput) {
		/* Nb of output bytes decoded */
		return (int) (((char *)op) - dst);
	}
	/* Nb of input bytes read */
	return (int) (((const char *)ip) - src);

	/* Overflow error detected */
_output_error:
	return (int) (-(((const char *)ip) - src)) - 1;
}

static FORCE_INLINE int LZ4_decompress_generic(
	 const char * const src,
	 char * const dst,
	 int srcSize,
		/*
		 * If endOnInput == endOnInputSize,
		 * this value is `dstCapacity`
		 */
	 int outputSize,
	 /* endOnOutputSize, endOnInputSize */
	 enum endCondition_directive endOnInput,
	 /* full, partial */
	 enum earlyEnd_directive partialDecoding,
	 /* noDict, withPrefix64k, usingExtDict */
	 enum dict_directive dict,
	 /* always <= dst, == dst when no prefix */
	 const BYTE * const lowPrefix,
	 /* only if dict == usingExtDict */
	 const BYTE * const dictStart,
	 /* note : = 0 if noDict */
	 const size_t dictSize
	 )
{
	int decoded;
	const BYTE *ip = (const BYTE *) src;

	BYTE *op = (BYTE *) dst;

	DEBUGLOG(5, "%s (srcSize:%i, dstSize:%i)", __func__,
		 srcSize, outputSize);

	/* Special cases */
	assert(lowPrefix <= op);
	assert(src != NULL);

	/* Empty output buffer */
	if ((endOnInput) && (unlikely(outputSize == 0)))
		return ((srcSize == 1) && (*ip == 0)) ? 0 : -1;

	if ((!endOnInput) && (unlikely(outputSize == 0)))
		return (*ip == 0 ? 1 : -1);

	if ((endOnInput) && unlikely(srcSize == 0))
		return -1;

	decoded = lz4p_decompress(ip, op, srcSize, outputSize, true, false);

	if (decoded <= 0) {
		pr_err("lz4raw_decode_buffer err decode\n");
		decoded = LZ4_decompress_generic_origin(src, dst, srcSize, outputSize, endOnInput, partialDecoding, dict, lowPrefix, dictStart, dictSize);
		if (decoded == 0)
			pr_err("LZ4_decompress_generic_origin err decode\n");
	}

	return decoded;
}


int LZ4P_decompress_safe(const char *source, char *dest,
	int compressedSize, int maxDecompressedSize, void *ctx)
{
	return LZ4_decompress_generic(source, dest,
					compressedSize, maxDecompressedSize,
					endOnInputSize, decode_full_block,
					noDict, (BYTE *)dest, NULL, 0);
}

/* ===== streaming decompression functions ===== */

#ifndef STATIC
EXPORT_SYMBOL(LZ4P_decompress_safe);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_DESCRIPTION("LZ4 decompressor");
#endif

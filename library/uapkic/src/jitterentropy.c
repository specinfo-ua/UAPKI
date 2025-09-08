/*
 * Copyright 2021 The UAPKI Project Authors.
 * Copyright Stephan Mueller <smueller@chronox.de>, 2014 - 2020
 *
 * Redistributionand use in sourceand binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditionsand the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditionsand the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES(INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
 * OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT(INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define FILE_MARKER "uapkic/jitterentropy.c"

#include "jitterentropy-internal.h"

 /* Timer-less entropy source */
#ifdef JENT_CONF_ENABLE_INTERNAL_TIMER
#include "pthread-internal.h"
#endif /* JENT_CONF_ENABLE_INTERNAL_TIMER */

#include "byte-utils-internal.h"
#include "byte-array-internal.h"
#include "sha3.h"

#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#ifdef __MACH__
#include <assert.h>
#include <CoreServices/CoreServices.h>
#include <mach/mach.h>
#include <mach/mach_time.h>
#include <unistd.h>
#endif

#define SHA3_256_SIZE_DIGEST_BITS	256
#define SHA3_256_SIZE_DIGEST		(SHA3_256_SIZE_DIGEST_BITS >> 3)

/* The entropy pool */
struct rand_data
{
	/* all data values that are vital to maintain the security
	 * of the RNG are marked as SENSITIVE. A user must not
	 * access that information while the RNG executes its loops to
	 * calculate the next random value. */
	Sha3Ctx* sha3ctx;
	ByteArray *data; /* SENSITIVE Actual random number */
	uint64_t prev_time;		/* SENSITIVE Previous time stamp */
#define DATA_SIZE_BITS (SHA3_256_SIZE_DIGEST_BITS)
	uint64_t last_delta;		/* SENSITIVE stuck test */
	uint64_t last_delta2;		/* SENSITIVE stuck test */
	unsigned int osr;		/* Oversampling rate */
#define JENT_MEMORY_BLOCKS 64
#define JENT_MEMORY_BLOCKSIZE 32
#define JENT_MEMORY_ACCESSLOOPS 128
#define JENT_MEMORY_SIZE (JENT_MEMORY_BLOCKS*JENT_MEMORY_BLOCKSIZE)
	unsigned char* mem;		/* Memory access location with size of
					 * memblocks * memblocksize */
	unsigned int memlocation; 	/* Pointer to byte in *mem */
	unsigned int memblocks;		/* Number of memory blocks in *mem */
	unsigned int memblocksize; 	/* Size of one memory block in bytes */
	unsigned int memaccessloops;	/* Number of memory accesses per random
					 * bit generation */

					 /* Repetition Count Test */
	int rct_count;			/* Number of stuck values */

	/* Adaptive Proportion Test for a significance level of 2^-30 */
#define JENT_APT_CUTOFF		325	/* Taken from SP800-90B sec 4.4.2 */
#define JENT_APT_WINDOW_SIZE	512	/* Data window size */
	/* LSB of time stamp to process */
#define JENT_APT_LSB		16
#define JENT_APT_WORD_MASK	(JENT_APT_LSB - 1)
	unsigned int apt_observations;	/* Number of collected observations */
	unsigned int apt_count;		/* APT counter */
	unsigned int apt_base;		/* APT base reference */
	unsigned int apt_base_set : 1;	/* APT base reference set? */

	unsigned int fips_enabled : 1;
	unsigned int health_failure : 1;	/* Permanent health failure */
	unsigned int enable_notime : 1;	/* Use internal high-res timer */

#ifdef JENT_CONF_ENABLE_INTERNAL_TIMER
	volatile uint8_t notime_interrupt;	/* indicator to interrupt ctr */
	volatile uint64_t notime_timer;		/* high-res timer mock-up */
	uint64_t notime_prev_timer;		/* previous timer value */
	pthread_t notime_thread_id;		/* pthreads thread ID */
#endif /* JENT_CONF_ENABLE_INTERNAL_TIMER */
};

static inline void jent_get_nstime(uint64_t* out)
{
	uint64_t ticks = 0;
#if defined(_MSC_VER)
	ticks = __rdtsc();
#elif defined(__i386__)
	asm volatile("rdtsc" : "=A"(ticks));
#elif defined(__x86_64__) || defined(__amd64__)
	uint32_t low, high;
	asm volatile("rdtsc" : "=a"(low), "=d"(high));
	ticks = (((uint64_t)high) << 32) | low;
#elif defined(__MACH__)
	ticks = mach_absolute_time();
#elif defined(__ia64__)
	asm volatile("mov %0 = ar.itc" : "=r"(ticks));
#elif defined(__powerpc64__) || defined(__ppc64__)
	asm volatile("mfspr %0, 268" : "=r"(ticks));
#elif defined(__sparc64__)
	asm volatile("rdpr %%tick, %0;" : "=&r"(ticks));
#else
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
		ticks = ((uint64_t)ts.tv_sec) * 1000000000 + ts.tv_nsec;
	}
#endif
	*out = ticks;
}

static inline int jent_fips_enabled(void)
{
	return 1;
}

static inline void* jent_zalloc(size_t len)
{
	/* we have no secure memory allocation! Hence
	 * we do not set CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY */
	return calloc(len, 1);
}

static inline void jent_zfree(void* ptr, unsigned int len)
{
	if (ptr) {
		secure_zero(ptr, len);
		free(ptr);
	}
}

/***************************************************************************
 * Jitter RNG Static Definitions
 *
 * None of the following should be altered
 ***************************************************************************/

/*
 * JENT_POWERUP_TESTLOOPCOUNT needs some loops to identify edge
 * systems. 100 is definitely too little.
 *
 * SP800-90B requires at least 1024 initial test cycles.
 */
#define JENT_POWERUP_TESTLOOPCOUNT 1024

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/***************************************************************************
 * Adaptive Proportion Test
 *
 * This test complies with SP800-90B section 4.4.2.
 ***************************************************************************/

/**
 * Reset the APT counter
 *
 * @ec [in] Reference to entropy collector
 */
static void jent_apt_reset(JitentCtx *ec, unsigned int delta_masked)
{
	/* Reset APT counter */
	ec->apt_count = 0;
	ec->apt_base = delta_masked;
	ec->apt_observations = 0;
}

/**
 * Insert a new entropy event into APT
 *
 * @ec [in] Reference to entropy collector
 * @delta_masked [in] Masked time delta to process
 */
static void jent_apt_insert(JitentCtx *ec, unsigned int delta_masked)
{
	/* Initialize the base reference */
	if (!ec->apt_base_set) {
		ec->apt_base = delta_masked;
		ec->apt_base_set = 1;
		return;
	}

	if (delta_masked == ec->apt_base) {
		ec->apt_count++;

		if (ec->apt_count >= JENT_APT_CUTOFF)
			ec->health_failure = 1;
	}

	ec->apt_observations++;

	if (ec->apt_observations >= JENT_APT_WINDOW_SIZE)
		jent_apt_reset(ec, delta_masked);
}

/***************************************************************************
 * Stuck Test and its use as Repetition Count Test
 *
 * The Jitter RNG uses an enhanced version of the Repetition Count Test
 * (RCT) specified in SP800-90B section 4.4.1. Instead of counting identical
 * back-to-back values, the input to the RCT is the counting of the stuck
 * values during the generation of one Jitter RNG output block.
 *
 * The RCT is applied with an alpha of 2^{-30} compliant to FIPS 140-2 IG 9.8.
 *
 * During the counting operation, the Jitter RNG always calculates the RCT
 * cut-off value of C. If that value exceeds the allowed cut-off value,
 * the Jitter RNG output block will be calculated completely but discarded at
 * the end. The caller of the Jitter RNG is informed with an error code.
 ***************************************************************************/

/**
 * Repetition Count Test as defined in SP800-90B section 4.4.1
 *
 * @ec [in] Reference to entropy collector
 * @stuck [in] Indicator whether the value is stuck
 */
static void jent_rct_insert(JitentCtx *ec, int stuck)
{
	/*
	 * If we have a count less than zero, a previous RCT round identified
	 * a failure. We will not overwrite it.
	 */
	if (ec->rct_count < 0)
		return;

	if (stuck) {
		ec->rct_count++;

		/*
		 * The cutoff value is based on the following consideration:
		 * alpha = 2^-30 as recommended in FIPS 140-2 IG 9.8.
		 * In addition, we require an entropy value H of 1/OSR as this
		 * is the minimum entropy required to provide full entropy.
		 * Note, we collect 64 * OSR deltas for inserting them into
		 * the entropy pool which should then have (close to) 64 bits
		 * of entropy.
		 *
		 * Note, ec->rct_count (which equals to value B in the pseudo
		 * code of SP800-90B section 4.4.1) starts with zero. Hence
		 * we need to subtract one from the cutoff value as calculated
		 * following SP800-90B.
		 */
		if ((unsigned int)ec->rct_count >= (31 * ec->osr)) {
			ec->rct_count = -1;
			ec->health_failure = 1;
		}
	} else {
		ec->rct_count = 0;
	}
}

/**
 * Is there an RCT health test failure?
 *
 * @ec [in] Reference to entropy collector
 *
 * @return
 * 	0 No health test failure
 * 	1 Permanent health test failure
 */
static int jent_rct_failure(JitentCtx *ec)
{
	if (ec->rct_count < 0)
		return 1;
	return 0;
}

static inline uint64_t jent_delta(uint64_t prev, uint64_t next)
{
	return (next - prev);
}

/**
 * Stuck test by checking the:
 * 	1st derivative of the jitter measurement (time delta)
 * 	2nd derivative of the jitter measurement (delta of time deltas)
 * 	3rd derivative of the jitter measurement (delta of delta of time deltas)
 *
 * All values must always be non-zero.
 *
 * @ec [in] Reference to entropy collector
 * @current_delta [in] Jitter time delta
 *
 * @return
 * 	0 jitter measurement not stuck (good bit)
 * 	1 jitter measurement stuck (reject bit)
 */
static unsigned int jent_stuck(JitentCtx *ec, uint64_t current_delta)
{
	uint64_t delta2 = jent_delta(ec->last_delta, current_delta);
	uint64_t delta3 = jent_delta(ec->last_delta2, delta2);
	unsigned int delta_masked = current_delta & JENT_APT_WORD_MASK;

	ec->last_delta = current_delta;
	ec->last_delta2 = delta2;

	/*
	 * Insert the result of the comparison of two back-to-back time
	 * deltas.
	 */
	jent_apt_insert(ec, delta_masked);

	if (!current_delta || !delta2 || !delta3) {
		/* RCT with a stuck bit */
		jent_rct_insert(ec, 1);
		return 1;
	}

	/* RCT with a non-stuck bit */
	jent_rct_insert(ec, 0);

	return 0;
}

/**
 * Report any health test failures
 *
 * @ec [in] Reference to entropy collector
 *
 * @return
 * 	0 No health test failure
 * 	1 Permanent health test failure
 */
static int jent_health_failure(JitentCtx *ec)
{
	/* Test is only enabled in FIPS mode */
	if (!ec->fips_enabled)
		return 0;

	return ec->health_failure;
}


#ifdef JENT_CONF_ENABLE_INTERNAL_TIMER

/***************************************************************************
 * Timer-less timer replacement
 *
 * If there is no high-resolution hardware timer available, we create one
 * ourselves. This logic is only used when the initialization identifies
 * that no suitable time source is available.
 ***************************************************************************/

static int jent_force_internal_timer = 0;

/**
 * Timer-replacement loop
 *
 * @brief The measurement loop triggers the read of the value from the
 * counter function. It conceptually acts as the low resolution
 * sampleS timer from a ring oscillator.
 */
static void *jent_notime_sample_timer(void *arg)
{
	JitentCtx *ec = (JitentCtx *)arg;

	ec->notime_timer = 0;

	while (1) {
		if (ec->notime_interrupt)
			return NULL;

		ec->notime_timer++;
	}

	return NULL;
}

/*
 * Enable the clock: spawn a new thread that holds a counter.
 *
 * Note, although creating a thread is expensive, we do that every time a
 * caller wants entropy from us and terminate the thread afterwards. This
 * is to ensure an attacker cannot easily identify the ticking thread.
 */
static inline int jent_notime_settick(JitentCtx *ec)
{
	ec->notime_interrupt = 0;
	ec->notime_prev_timer = 0;
	ec->notime_timer = 0;

	return -pthread_create(&ec->notime_thread_id,
			       NULL, jent_notime_sample_timer, ec);
}

static inline void jent_notime_unsettick(JitentCtx *ec)
{
	ec->notime_interrupt = 1;
	pthread_join(ec->notime_thread_id, NULL);
	pthread_detach(ec->notime_thread_id);
}

static inline void jent_get_nstime_internal(JitentCtx *ec, uint64_t *out)
{
	if (ec->enable_notime) {
		/*
		 * Allow the counting thread to be initialized and guarantee
		 * that it ticked since last time we looked.
		 *
		 * Note, we do not use an atomic operation here for reading
		 * jent_notime_timer since if this integer is garbled, it even
		 * adds to entropy. But on most architectures, read/write
		 * of an uint64_t should be atomic anyway.
		 */
		while (ec->notime_timer == ec->notime_prev_timer)
			;

		ec->notime_prev_timer = ec->notime_timer;
		*out = ec->notime_prev_timer;
	} else {
		jent_get_nstime(out);
	}
}

static int jent_time_entropy_init(unsigned int enable_notime);
static int jent_notime_enable(JitentCtx *ec, unsigned int flags)
{
	/* Use internal timer */
	if (jent_force_internal_timer || (flags & JENT_FORCE_INTERNAL_TIMER)) {
		/* Self test not run yet */
		if (!jent_force_internal_timer && jent_time_entropy_init(1))
			return EHEALTH;

		ec->enable_notime = 1;
	}

	return 0;
}

#else /* JENT_CONF_ENABLE_INTERNAL_TIMER */

static inline void jent_get_nstime_internal(JitentCtx *ec, uint64_t *out)
{
	(void)ec;
	jent_get_nstime(out);
}

static inline int jent_notime_enable(JitentCtx *ec, unsigned int flags)
{
	(void)ec;

	/* If we force the timer-less noise source, we return an error */
	if (flags & JENT_FORCE_INTERNAL_TIMER)
		return EHEALTH;

	return 0;
}

static inline int jent_notime_settick(JitentCtx *ec)
{
	(void)ec;
	return 0;
}

static inline void jent_notime_unsettick(JitentCtx *ec) { (void)ec; }

#endif /* JENT_CONF_ENABLE_INTERNAL_TIMER */

/***************************************************************************
 * Noise sources
 ***************************************************************************/

/**
 * Update of the loop count used for the next round of
 * an entropy collection.
 *
 * @ec [in] entropy collector struct -- may be NULL
 * @bits [in] is the number of low bits of the timer to consider
 * @min [in] is the number of bits we shift the timer value to the right at
 *	     the end to make sure we have a guaranteed minimum value
 *
 * @return Newly calculated loop counter
 */
static uint64_t jent_loop_shuffle(JitentCtx *ec,
				  unsigned int bits, unsigned int min)
{
	uint64_t time = 0;
	uint64_t shuffle = 0;
	unsigned int i = 0;
	unsigned int mask = (1U<<bits) - 1;

	/*
	 * Mix the current state of the random number into the shuffle
	 * calculation to balance that shuffle a bit more.
	 */
	if (ec) {
		jent_get_nstime_internal(ec, &time);
		time ^= ec->data->buf[0];
	}

	/*
	 * We fold the time value as much as possible to ensure that as many
	 * bits of the time stamp are included as possible.
	 */
	for (i = 0; ((DATA_SIZE_BITS + bits - 1) / bits) > i; i++) {
		shuffle ^= time & mask;
		time = time >> bits;
	}

	/*
	 * We add a lower boundary value to ensure we have a minimum
	 * RNG loop count.
	 */
	return (shuffle + ((uint64_t)1<<min));
}

/**
 * CPU Jitter noise source -- this is the noise source based on the CPU
 * 			      execution time jitter
 *
 * This function injects the individual bits of the time value into the
 * entropy pool using a hash.
 *
 * @ec [in] entropy collector struct -- may be NULL
 * @time [in] time stamp to be injected
 * @loop_cnt [in] if a value not equal to 0 is set, use the given value as
 *		  number of loops to perform the hash operation
 * @stuck [in] Is the time stamp identified as stuck?
 *
 * Output:
 * updated hash context
 */
static void jent_hash_time(JitentCtx *ec, uint64_t time,
			   uint64_t loop_cnt, unsigned int stuck)
{
	uint64_t j = 0;
#define MAX_HASH_LOOP 3
#define MIN_HASH_LOOP 0
	uint64_t lfsr_loop_cnt =
		jent_loop_shuffle(ec, MAX_HASH_LOOP, MIN_HASH_LOOP);
	ByteArray* tmp = NULL;
	ByteArray t2 = {NULL, sizeof(uint64_t) };

	/*
	 * testing purposes -- allow test app to set the counter, not
	 * needed during runtime
	 */
	if (loop_cnt)
		lfsr_loop_cnt = loop_cnt;

	for (j = 0; j < lfsr_loop_cnt; j++) {
		sha3_update(ec->sha3ctx, ec->data);
		t2.buf = (uint8_t*)&time;
		sha3_update(ec->sha3ctx, &t2);
		t2.buf = (uint8_t*)&j;
		sha3_update(ec->sha3ctx, &t2);
		sha3_final(ec->sha3ctx, &tmp);

		/*
		 * If the time stamp is stuck, do not finally insert the value
		 * into the entropy pool. Although this operation should not do
		 * any harm even when the time stamp has no entropy, SP800-90B
		 * requires that any conditioning operation to have an identical
		 * amount of input data according to section 3.1.5.
		 */
		if (tmp) {
			if (stuck) {
				ba_free_private(tmp);
				tmp = ec->data;
			}
			else {
				ba_free_private(ec->data);
				ec->data = tmp;
			}
		}
	}
}

/**
 * Memory Access noise source -- this is a noise source based on variations in
 * 				 memory access times
 *
 * This function performs memory accesses which will add to the timing
 * variations due to an unknown amount of CPU wait states that need to be
 * added when accessing memory. The memory size should be larger than the L1
 * caches as outlined in the documentation and the associated testing.
 *
 * The L1 cache has a very high bandwidth, albeit its access rate is  usually
 * slower than accessing CPU registers. Therefore, L1 accesses only add minimal
 * variations as the CPU has hardly to wait. Starting with L2, significant
 * variations are added because L2 typically does not belong to the CPU any more
 * and therefore a wider range of CPU wait states is necessary for accesses.
 * L3 and real memory accesses have even a wider range of wait states. However,
 * to reliably access either L3 or memory, the ec->mem memory must be quite
 * large which is usually not desirable.
 *
 * @ec [in] Reference to the entropy collector with the memory access data -- if
 *	    the reference to the memory block to be accessed is NULL, this noise
 *	    source is disabled
 * @loop_cnt [in] if a value not equal to 0 is set, use the given value as
 *		  number of loops to perform the hash operation
 */
static void jent_memaccess(struct rand_data *ec, uint64_t loop_cnt)
{
	unsigned int wrap = 0;
	uint64_t i = 0;
#define MAX_ACC_LOOP_BIT 7
#define MIN_ACC_LOOP_BIT 0
	uint64_t acc_loop_cnt =
		jent_loop_shuffle(ec, MAX_ACC_LOOP_BIT, MIN_ACC_LOOP_BIT);

	if (NULL == ec || NULL == ec->mem)
		return;
	wrap = ec->memblocksize * ec->memblocks;

	/*
	 * testing purposes -- allow test app to set the counter, not
	 * needed during runtime
	 */
	if (loop_cnt)
		acc_loop_cnt = loop_cnt;

	for (i = 0; i < (ec->memaccessloops + acc_loop_cnt); i++) {
		unsigned char *tmpval = ec->mem + ec->memlocation;
		/*
		 * memory access: just add 1 to one byte,
		 * wrap at 255 -- memory access implies read
		 * from and write to memory location
		 */
		*tmpval = (unsigned char)((*tmpval + 1) & 0xff);
		/*
		 * Addition of memblocksize - 1 to pointer
		 * with wrap around logic to ensure that every
		 * memory location is hit evenly
		 */
		ec->memlocation = ec->memlocation + ec->memblocksize - 1;
		ec->memlocation = ec->memlocation % wrap;
	}
}

/***************************************************************************
 * Start of entropy processing logic
 ***************************************************************************/

/**
 * This is the heart of the entropy generation: calculate time deltas and
 * use the CPU jitter in the time deltas. The jitter is injected into the
 * entropy pool.
 *
 * WARNING: ensure that ->prev_time is primed before using the output
 * 	    of this function! This can be done by calling this function
 * 	    and not using its result.
 *
 * @ec [in] Reference to entropy collector
 *
 * @return: result of stuck test
 */
static unsigned int jent_measure_jitter(struct rand_data *ec)
{
	uint64_t time = 0;
	uint64_t current_delta = 0;
	unsigned int stuck;

	/* Invoke one noise source before time measurement to add variations */
	jent_memaccess(ec, 0);

	/*
	 * Get time stamp and calculate time delta to previous
	 * invocation to measure the timing variations
	 */
	jent_get_nstime_internal(ec, &time);
	current_delta = jent_delta(ec->prev_time, time);
	ec->prev_time = time;

	/* Check whether we have a stuck measurement. */
	stuck = jent_stuck(ec, current_delta);

	/* Now call the next noise sources which also injects the data */
	jent_hash_time(ec, current_delta, 0, stuck);

	return stuck;
}

/**
 * Generator of one 256 bit random number
 * Function fills rand_data->data
 *
 * @ec [in] Reference to entropy collector
 */
static void jent_random_data(struct rand_data *ec)
{
	unsigned int k = 0;

	/* priming of the ->prev_time value */
	jent_measure_jitter(ec);

	while (1) {
		/* If a stuck measurement is received, repeat measurement */
		if (jent_measure_jitter(ec))
			continue;

		/*
		 * We multiply the loop value with ->osr to obtain the
		 * oversampling rate requested by the caller
		 */
		if (++k >= (DATA_SIZE_BITS * ec->osr))
			break;
	}
}

/***************************************************************************
 * Random Number Generation
 ***************************************************************************/

/**
 * Entry function: Obtain entropy for the caller.
 *
 * This function invokes the entropy gathering logic as often to generate
 * as many bytes as requested by the caller. The entropy gathering logic
 * creates 64 bit per invocation.
 *
 * This function truncates the last 64 bit entropy value output to the exact
 * size specified by the caller.
 *
 * @ec [in] Reference to entropy collector
 * @data [out] pointer to buffer for storing random data -- buffer must
 *	       already exist
 * @len [in] size of the buffer, specifying also the requested number of random
 *	     in bytes
 *
 * @return 0 or an error
 *
 * The following error codes can occur:
 *	-1	entropy_collector is NULL
 *	-2	RCT failed
 *	-3	APT test failed
 *	-4	The timer cannot be initialized
 */
int jent_read_entropy(JitentCtx *ec, unsigned char *data, size_t len)
{
	uint8_t *p = data;
	int ret = 0;

	if (NULL == ec)
		return -1;

	if (jent_notime_settick(ec))
		return -4;

	while (len) {
		size_t tocopy;

		jent_random_data(ec);

		if (jent_health_failure(ec)) {
			if (jent_rct_failure(ec))
				ret = -2;
			else
				ret = -3;

			goto err;
		}

		tocopy = min(DATA_SIZE_BITS >> 3, len);
		memcpy(p, ba_get_buf_const(ec->data), tocopy);

		p += tocopy;
		len -= tocopy;
	}

	/*
	 * To be on the safe side, we generate one more round of entropy
	 * which we do not give out to the caller. That round shall ensure
	 * that in case the calling application crashes, memory dumps, pages
	 * out, or due to the CPU Jitter RNG lingering in memory for long
	 * time without being moved and an attacker cracks the application,
	 * all he reads in the entropy pool is a value that is NEVER EVER
	 * being used for anything. Thus, he does NOT see the previous value
	 * that was returned to the caller for cryptographic purposes.
	 */
	/*
	 * If we use secured memory, do not use that precaution as the secure
	 * memory protects the entropy pool. Moreover, note that using this
	 * call reduces the speed of the RNG by up to half
	 */
#ifndef CONFIG_CRYPTO_CPU_JITTERENTROPY_SECURE_MEMORY
	jent_random_data(ec);
#endif

err:
	jent_notime_unsettick(ec);
	return ret;
}

/***************************************************************************
 * Initialization logic
 ***************************************************************************/
JitentCtx *jent_entropy_collector_alloc(unsigned int osr,
					       unsigned int flags)
{
	struct rand_data *entropy_collector;

	entropy_collector = jent_zalloc(sizeof(struct rand_data));
	if (NULL == entropy_collector)
		return NULL;

	entropy_collector->sha3ctx = sha3_alloc(SHA3_VARIANT_256);
	if (NULL == entropy_collector->sha3ctx)
		goto err;

	entropy_collector->data = ba_alloc_by_len(SHA3_256_SIZE_DIGEST);
	if (NULL == entropy_collector->sha3ctx)
		goto err;

	if (!(flags & JENT_DISABLE_MEMORY_ACCESS)) {
		/* Allocate memory for adding variations based on memory
		 * access
		 */
		entropy_collector->mem = 
			(unsigned char *)jent_zalloc(JENT_MEMORY_SIZE);
		if (entropy_collector->mem == NULL)
			goto err;

		entropy_collector->memblocksize = JENT_MEMORY_BLOCKSIZE;
		entropy_collector->memblocks = JENT_MEMORY_BLOCKS;
		entropy_collector->memaccessloops = JENT_MEMORY_ACCESSLOOPS;
	}

	/* verify and set the oversampling rate */
	if (osr == 0)
		osr = 1; /* minimum sampling rate is 1 */
	entropy_collector->osr = osr;

	if (jent_fips_enabled())
		entropy_collector->fips_enabled = 1;

	/* Use timer-less noise source */
	if (jent_notime_enable(entropy_collector, flags))
		goto err;

	/* fill the data pad with non-zero values */
	if (jent_notime_settick(entropy_collector))
		goto err;
	jent_random_data(entropy_collector);
	jent_notime_unsettick(entropy_collector);

	return entropy_collector;

err:
	sha3_free(entropy_collector->sha3ctx);
	ba_free(entropy_collector->data);
	jent_zfree(entropy_collector->mem, JENT_MEMORY_SIZE);
	jent_zfree(entropy_collector, sizeof(struct rand_data));
	return NULL;
}

void jent_entropy_collector_free(JitentCtx *entropy_collector)
{
	if (entropy_collector != NULL) {
		sha3_free(entropy_collector->sha3ctx);
		ba_free_private(entropy_collector->data);
		jent_zfree(entropy_collector->mem, JENT_MEMORY_SIZE);
		jent_zfree(entropy_collector, sizeof(struct rand_data));
	}
}

static int jent_time_entropy_init(unsigned int enable_notime)
{
	int i;
	uint64_t delta_sum = 0;
	uint64_t old_delta = 0;
	unsigned int nonstuck = 0;
	int time_backwards = 0;
	int count_mod = 0;
	int count_stuck = 0;
	int ret = 0;
	JitentCtx *ec;

	ec = jent_zalloc(sizeof(struct rand_data));
	if (NULL == ec)
		return ENOMEMORY;

	ec->sha3ctx = sha3_alloc(SHA3_VARIANT_256);
	if (NULL == ec->sha3ctx) {
		ret = ENOMEMORY;
		goto out;
	}

	ec->data = ba_alloc_by_len(SHA3_256_SIZE_DIGEST);
	if (NULL == ec->sha3ctx){
		ret = ENOMEMORY;
		goto out;
	}

	if (enable_notime) {
		ec->enable_notime = 1;
		jent_notime_settick(ec);
	}

	/* Required for RCT */
	ec->osr = 1;
	if (jent_fips_enabled())
		ec->fips_enabled = 1;

	/* We could perform statistical tests here, but the problem is
	 * that we only have a few loop counts to do testing. These
	 * loop counts may show some slight skew and we produce
	 * false positives.
	 *
	 * Moreover, only old systems show potentially problematic
	 * jitter entropy that could potentially be caught here. But
	 * the RNG is intended for hardware that is available or widely
	 * used, but not old systems that are long out of favor. Thus,
	 * no statistical tests.
	 */

	/*
	 * We could add a check for system capabilities such as clock_getres or
	 * check for CONFIG_X86_TSC, but it does not make much sense as the
	 * following sanity checks verify that we have a high-resolution
	 * timer.
	 */

#define CLEARCACHE 100
	for (i = 0; (JENT_POWERUP_TESTLOOPCOUNT + CLEARCACHE) > i; i++) {
		uint64_t time = 0;
		uint64_t time2 = 0;
		uint64_t delta = 0;
		unsigned int lowdelta = 0;
		unsigned int stuck;

		/* Invoke core entropy collection logic */
		jent_get_nstime_internal(ec, &time);
		ec->prev_time = time;
		jent_memaccess(ec, 0);
		jent_hash_time(ec, time, 0, 0);
		jent_get_nstime_internal(ec, &time2);

		/* test whether timer works */
		if (!time || !time2) {
			ret = ENOTIME;
			goto out;
		}
		delta = jent_delta(time, time2);
		/*
		 * test whether timer is fine grained enough to provide
		 * delta even when called shortly after each other -- this
		 * implies that we also have a high resolution timer
		 */
		if (!delta) {
			ret = ECOARSETIME;
			goto out;
		}

		stuck = jent_stuck(ec, delta);

		/*
		 * up to here we did not modify any variable that will be
		 * evaluated later, but we already performed some work. Thus we
		 * already have had an impact on the caches, branch prediction,
		 * etc. with the goal to clear it to get the worst case
		 * measurements.
		 */
		if (CLEARCACHE > i)
			continue;

		if (stuck)
			count_stuck++;
		else {
			nonstuck++;

			/*
			 * Ensure that the APT succeeded.
			 *
			 * With the check below that count_stuck must be less
			 * than 10% of the overall generated raw entropy values
			 * it is guaranteed that the APT is invoked at
			 * floor((JENT_POWERUP_TESTLOOPCOUNT * 0.9) / 64) == 14
			 * times.
			 */
			if ((nonstuck % JENT_APT_WINDOW_SIZE) == 0) {
				jent_apt_reset(ec,
					       delta & JENT_APT_WORD_MASK);
				if (jent_health_failure(ec)) {
					ret = EHEALTH;
					goto out;
				}
			}
		}

		/* Validate RCT */
		if (jent_rct_failure(ec)) {
			ret = ERCT;
			goto out;
		}

		/* test whether we have an increasing timer */
		if (!(time2 > time))
			time_backwards++;

		/* use 32 bit value to ensure compilation on 32 bit arches */
		lowdelta = (unsigned int)(time2 - time);
		if (!(lowdelta % 100))
			count_mod++;

		/*
		 * ensure that we have a varying delta timer which is necessary
		 * for the calculation of entropy -- perform this check
		 * only after the first loop is executed as we need to prime
		 * the old_data value
		 */
		if (delta > old_delta)
			delta_sum += (delta - old_delta);
		else
			delta_sum += (old_delta - delta);
		old_delta = delta;
	}

	/*
	 * we allow up to three times the time running backwards.
	 * CLOCK_REALTIME is affected by adjtime and NTP operations. Thus,
	 * if such an operation just happens to interfere with our test, it
	 * should not fail. The value of 3 should cover the NTP case being
	 * performed during our test run.
	 */
	if (time_backwards > 3) {
		ret = ENOMONOTONIC;
		goto out;
	}

	/*
	 * Variations of deltas of time must on average be larger
	 * than 1 to ensure the entropy estimation
	 * implied with 1 is preserved
	 */
	if ((delta_sum) <= 1) {
		ret = EMINVARVAR;
		goto out;
	}

	/*
	 * Ensure that we have variations in the time stamp below 10 for at
	 * least 10% of all checks -- on some platforms, the counter increments
	 * in multiples of 100, but not always
	 */
	if ((JENT_POWERUP_TESTLOOPCOUNT/10 * 9) < count_mod) {
		ret = ECOARSETIME;
		goto out;
	}

	/*
	 * If we have more than 90% stuck results, then this Jitter RNG is
	 * likely to not work well.
	 */
	if ((JENT_POWERUP_TESTLOOPCOUNT/10 * 9) < count_stuck)
		ret = ESTUCK;

out:
	if (enable_notime)
		jent_notime_unsettick(ec);

	sha3_free(ec->sha3ctx);
	ba_free_private(ec->data);
	jent_zfree(ec, sizeof(struct rand_data));

	return ret;
}

int jent_entropy_init(void)
{
	int ret;

	ret = jent_time_entropy_init(0);

#ifdef JENT_CONF_ENABLE_INTERNAL_TIMER
	jent_force_internal_timer = 0;
	if (ret) {
		ret = jent_time_entropy_init(1);
		if (!ret)
			jent_force_internal_timer = 1;
	}
#endif /* JENT_CONF_ENABLE_INTERNAL_TIMER */

	return ret;
}

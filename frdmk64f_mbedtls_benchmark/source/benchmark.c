/*
 *  Benchmark demonstration program
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0
 *  Copyright 2017, 2021 NXP. Not a Contribution
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*******************************************************************************
 * Includes
 ******************************************************************************/

#include MBEDTLS_CONFIG_FILE


#include "mbedtls/version.h"
#include <stdio.h>
#include "fsl_debug_console.h"
#include "fsl_clock.h"
#include "pin_mux.h"
#include "clock_config.h"
#include "board.h"
#include "ksdk_mbedtls.h"

#define mbedtls_printf PRINTF
#define mbedtls_snprintf snprintf
#define MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED -0x0072 /**< The requested feature is not supported by the platform */     
#define mbedtls_exit(x) \
    do                  \
    {                   \
    } while (1)
#define mbedtls_free free
#define fflush(x) \
    do            \
    {             \
    } while (0)


#include <string.h>
#include <stdlib.h>

#include "mbedtls/timing.h"

#include "mbedtls/md4.h"
#include "mbedtls/md5.h"
#include "mbedtls/ripemd160.h"
#include "mbedtls/sha1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/sha512.h"

#include "mbedtls/arc4.h"
#include "mbedtls/des.h"
#include "mbedtls/aes.h"
#include "mbedtls/aria.h"
#include "mbedtls/blowfish.h"
#include "mbedtls/camellia.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ccm.h"
#include "mbedtls/chachapoly.h"
#include "mbedtls/cmac.h"
#include "mbedtls/poly1305.h"

#include "mbedtls/havege.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/hmac_drbg.h"

#include "mbedtls/rsa.h"
#include "mbedtls/dhm.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/ecdh.h"

#include "mbedtls/error.h"

#include "fsl_device_registers.h"
/*******************************************************************************
 * Definitions
 ******************************************************************************/

#define CORE_CLK_FREQ CLOCK_GetFreq(kCLOCK_CoreSysClk)

/*
 * For heap usage estimates, we need an estimate of the overhead per allocated
 * block. ptmalloc2/3 (used in gnu libc for instance) uses 2 size_t per block,
 * so use that as our baseline.
 */
#define MEM_BLOCK_OVERHEAD  ( 2 * sizeof( size_t ) )

/*
 * Size to use for the alloc buffer if MEMORY_BUFFER_ALLOC_C is defined.
 */
#define HEAP_SIZE       (1u << 16)  /* 64k */

#define BUFSIZE         1024
#define HEADER_FORMAT   "  %-24s :  "
#define TITLE_LEN       25

#define OPTIONS                                                         \
    "md4, md5, ripemd160, sha1, sha256, sha512,\n"                      \
    "arc4, des3, des, camellia, blowfish, chacha20,\n"                  \
    "aes_cbc, aes_gcm, aes_ccm, aes_xts, chachapoly,\n"                 \
    "aes_cmac, des3_cmac, poly1305\n"                                   \
    "havege, ctr_drbg, hmac_drbg\n"                                     \
    "rsa, dhm, ecdsa, ecdh.\n"

#define PRINT_ERROR                                                     \
        mbedtls_strerror( ret, ( char * )tmp, sizeof( tmp ) );          \
        mbedtls_printf( "FAILED: %s\n", tmp );

#define TIME_AND_TSC(TITLE, CODE)                                                                        \
    do                                                                                                   \
    {                                                                                                    \
        uint32_t ii, jj;                                                                                 \
        uint64_t tsc1, tsc2;                                                                             \
        int ret = 0;                                                                                     \
                                                                                                         \
        mbedtls_printf(HEADER_FORMAT, TITLE);                                                            \
        fflush(stdout);                                                                                  \
                                                                                                         \
        benchmark_mbedtls_set_alarm(1);                                                                  \
        tsc1 = benchmark_mbedtls_timing_hardclock();                                                     \
        for (ii = 1; ret == 0 && !benchmark_mbedtls_timing_alarmed; ii++)                                \
        {                                                                                                \
            ret = CODE;                                                                                  \
            benchmark_mbedtls_poll_alarm();                                                              \
        }                                                                                                \
                                                                                                         \
        tsc2 = benchmark_mbedtls_timing_hardclock();                                                     \
        for (jj = 0; ret == 0 && jj < 1024; jj++)                                                        \
        {                                                                                                \
            ret = CODE;                                                                                  \
        }                                                                                                \
                                                                                                         \
        if (ret != 0)                                                                                    \
        {                                                                                                \
            PRINT_ERROR;                                                                                 \
        }                                                                                                \
        else                                                                                             \
        {                                                                                                \
            mbedtls_printf("%6.2f KB/s,  %6.2f cycles/byte\r\n",                                         \
                           (ii * BUFSIZE / 1024) / (((float)(tsc2 - tsc1)) / CLOCK_GetCoreSysClkFreq()), \
                           (((float)(benchmark_mbedtls_timing_hardclock() - tsc2)) / (jj * BUFSIZE)));   \
        }                                                                                                \
    } while (0)

#define MEMORY_MEASURE_INIT
#define MEMORY_MEASURE_PRINT( title_len )

#define TIME_PUBLIC(TITLE, TYPE, CODE)                                                                                \
    do                                                                                                                \
    {                                                                                                                 \
        uint32_t ii;                                                                                                  \
        uint64_t tsc;                                                                                                 \
        int ret;                                                                                                      \
        MEMORY_MEASURE_INIT;                                                                                          \
                                                                                                                      \
        mbedtls_printf(HEADER_FORMAT, TITLE);                                                                         \
        fflush(stdout);                                                                                               \
        benchmark_mbedtls_set_alarm(3);                                                                               \
                                                                                                                      \
        ret = 0;                                                                                                      \
        tsc = benchmark_mbedtls_timing_hardclock();                                                                   \
        for (ii = 1; !benchmark_mbedtls_timing_alarmed && !ret; ii++)                                                 \
        {                                                                                                             \
            CODE;                                                                                                     \
            benchmark_mbedtls_poll_alarm();                                                                           \
        }                                                                                                             \
                                                                                                                      \
        if (ret != 0)                                                                                                 \
        {                                                                                                             \
            PRINT_ERROR;                                                                                              \
        }                                                                                                             \
        else                                                                                                          \
        {                                                                                                             \
            mbedtls_printf("%6.2f " TYPE "/s",                                                                        \
                           ((float)ii) / ((benchmark_mbedtls_timing_hardclock() - tsc) / CLOCK_GetCoreSysClkFreq())); \
            MEMORY_MEASURE_PRINT(sizeof(TYPE) + 1);                                                                   \
            mbedtls_printf("\r\n");                                                                                   \
        }                                                                                                             \
    } while (0)

/*******************************************************************************
 * Prototypes
 ******************************************************************************/

/*******************************************************************************
 * Variables
 ******************************************************************************/

/*******************************************************************************
 * Code
 ******************************************************************************/
static int myrand( void *rng_state, unsigned char *output, size_t len )
{
    size_t use_len;
    int rnd;

    if( rng_state != NULL )
        rng_state  = NULL;

    while( len > 0 )
    {
        use_len = len;
        if( use_len > sizeof(int) )
            use_len = sizeof(int);

        rnd = rand();
        memcpy( output, &rnd, use_len );
        output += use_len;
        len -= use_len;
    }

    return( 0 );
}

#define CHECK_AND_CONTINUE( R )                                         \
    {                                                                   \
        int CHECK_AND_CONTINUE_ret = ( R );                             \
        if( CHECK_AND_CONTINUE_ret == MBEDTLS_ERR_PLATFORM_FEATURE_UNSUPPORTED ) { \
            mbedtls_printf( "Feature not supported. Skipping.\n" );     \
            continue;                                                   \
        }                                                               \
        else if( CHECK_AND_CONTINUE_ret != 0 ) {                        \
            mbedtls_exit( 1 );                                          \
        }                                                               \
    }

/*
 * Clear some memory that was used to prepare the context
 */
void ecp_clear_precomputed( mbedtls_ecp_group *grp )
{
    if( grp->T != NULL )
    {
        size_t i;
        for( i = 0; i < grp->T_size; i++ )
            mbedtls_ecp_point_free( &grp->T[i] );
        mbedtls_free( grp->T );
    }
    grp->T = NULL;
    grp->T_size = 0;
}

/* NXP: Move buffer to NON-CACHED memory because of HW accel */ 
    unsigned char buf[BUFSIZE];    /* DCACHE */

static int set_ecp_curve( const char *string, mbedtls_ecp_curve_info *curve )
{
    const mbedtls_ecp_curve_info *found =
        mbedtls_ecp_curve_info_from_name( string );
    if( found != NULL )
    {
        *curve = *found;
        return( 1 );
    }
    else
        return( 0 );
}

#define SHA256
#if defined SHA256
typedef struct {
    char sha256;
} todo_list;
#else
typedef struct {
    char md4, md5, ripemd160, sha1, sha256, sha512,
         arc4, des3, des,
         aes_cbc, aes_gcm, aes_ccm, aes_xts, chachapoly,
         aes_cmac, des3_cmac,
         aria, camellia, blowfish, chacha20,
         poly1305,
         havege, ctr_drbg, hmac_drbg,
         rsa, dhm, ecdsa, ecdh;
} todo_list;
#endif

static volatile uint32_t s_MsCount = 0U;
static volatile int benchmark_mbedtls_timing_alarmed;
static uint64_t s_Timeout;

/*!
 * @brief Milliseconds counter since last POR/reset.
 */
void SysTick_Handler(void)
{
    s_MsCount++;
}

static uint64_t benchmark_mbedtls_timing_hardclock(void)
{
    uint32_t currMsCount;
    uint32_t currTick;
    uint32_t loadTick;

    do
    {
        currMsCount = s_MsCount;
        currTick    = SysTick->VAL;
    } while (currMsCount != s_MsCount);

    loadTick = CLOCK_GetCoreSysClkFreq() / 1000U;
    return (((uint64_t)currMsCount) * loadTick) + loadTick - currTick;
}

static void benchmark_mbedtls_set_alarm(int seconds)
{
    benchmark_mbedtls_timing_alarmed = 0;
    s_Timeout                        = benchmark_mbedtls_timing_hardclock() + (seconds * CLOCK_GetCoreSysClkFreq());
}

static void benchmark_mbedtls_poll_alarm(void)
{
    if (benchmark_mbedtls_timing_hardclock() > s_Timeout)
    {
        benchmark_mbedtls_timing_alarmed = 1;
    }
}

static int bench_print_features(void)
{
    char *text;
    mbedtls_printf("mbedTLS version %s\r\n", MBEDTLS_VERSION_STRING);
    mbedtls_printf("fsys=%lu\r\n", ((CORE_CLK_FREQ)));
    mbedtls_printf("Using following implementations:\r\n");

    text = "MMCAU HW accelerated";

    mbedtls_printf("  SHA: %s\r\n", text);

    text = "MMCAU HW accelerated";

    mbedtls_printf("  AES: %s\r\n", text);

    text = "MMCAU HW accelerated";

    mbedtls_printf("  AES GCM: %s\r\n", text);

    text = "LTC HW accelerated";

    text = "MMCAU HW accelerated";

    mbedtls_printf("  DES: %s\r\n", text);

    text = "Software implementation";

    mbedtls_printf("  Asymmetric cryptography: %s\r\n", text);

    return 0;
}

int main( int argc, char *argv[] )
{
    int i;
    unsigned char tmp[200];
    char title[TITLE_LEN];
    todo_list todo;

    /* HW init */
    BOARD_InitBootPins();
    BOARD_InitBootClocks();
    BOARD_InitDebugConsole();
    if( CRYPTO_InitHardware() != kStatus_Success )
    {
        mbedtls_printf( "Initialization of crypto HW failed\n" );
        mbedtls_exit( MBEDTLS_EXIT_FAILURE );
    }

    /* Init SysTick module */
    /* call CMSIS SysTick function. It enables the SysTick interrupt at low priority */
    SysTick_Config(CLOCK_GetCoreSysClkFreq() / 1000U); /* 1 ms period */
    bench_print_features();

    /* Run all tests.*/
    memset(&todo, 1, sizeof(todo));

    mbedtls_printf( "\n" );

    memset( buf, 0xAA, sizeof( buf ) );
    memset( tmp, 0xBB, sizeof( tmp ) );

    TIME_AND_TSC( "SHA-256", mbedtls_sha256_ret( buf, BUFSIZE, tmp, 0 ) );
    PRINTF("  SHA-256: ");
    for(int i=0;i<32;i++){
		PRINTF("%c", tmp[i]);
	}

    mbedtls_printf( "\n" );

    while(1){
        char ch = GETCHAR();
        PUTCHAR(ch);
    }
}


/*
 * globals.cc
 *
 *  Created on: 14 Apr 2016
 *      Author: jakez
 */

#include "globals.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sys/types.h>
#include <sys/timeb.h>

#ifdef WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

//++++++++++++++++++ logging ++++++++++++++++++++
static bool globalTrace = true;
static bool fileTrace = false;
static FILE* logfile = 0;
static int noOftracedModules;
static char traced_modules[TRACE_MUDULE_SIZE][70];
static int error_trace_levels[TRACE_MUDULE_SIZE];
static int event_trace_levels[TRACE_MUDULE_SIZE];
static const char* error_loglvls_str[4] =
{
    "fatal_error_exit",
    "major_error_abort",
    "minor_error",
    "lwarnning_error"
};
static const char* event_loglvls_str[6] =
{
    "extevent_unexpected",
    "extevent",
    "intevent_important",
    "intevent",
    "verbose",
    "lvverbos"
};

void read_trace_levels(void)
{
    int i;
    int ret;
    char filename[100];
    noOftracedModules = 0;

    // this will be relative path  to project dir if you run it by ctrl_F5 in vs studio
    // if you want to run relative path to the exutable, you have to manually click it and run it,
    FILE* fptr = fopen("../../tracelevels.in", "r");
    if (fptr != NULL)
    {
        globalTrace = true;
        for (i = 0; i < TRACE_MUDULE_SIZE; i++)
        {
            ret = fscanf(fptr, "%s%d%d", traced_modules[i],
                &error_trace_levels[i], &event_trace_levels[i]);
            if (ret >= 1)
            {
                if (strcmp(traced_modules[i], "LOGFILE") == 0)
                {
                    printf(
                        "Logging all errors and events to file ./tmp%d.log\n",
                        (int)getpid());
                    fileTrace = true;
                    sprintf(filename, "./tmp%d.log", (int)getpid());
                    logfile = fopen(filename, "w+");
                    return;
                }
            }

            if (ferror(fptr))
                abort();

            //if we have less than TRACE_MUDULE_SIZE mudlues to trace, this will break loop
            if (feof(fptr))
                break;

            globalTrace = false;
        }
        noOftracedModules = i;
        if (i <= 1)
            globalTrace = true;
        printf("  globalTrace = %s \n", globalTrace ? "TRUE" : "FALSE");
    }
    else
    {
        globalTrace = true;
    }
    printf("globalTrace '%s', modules size '%d'\n",
        globalTrace ? "TRUE" : "FALSE", noOftracedModules);
    for (i = 0; i < noOftracedModules; i++)
        printf("%20s %2d %2d\n", traced_modules[i], error_trace_levels[i],
        event_trace_levels[i]);
}

// -1 not found, >0 = module index
static  int is_module_traced(const char* modulename)
{
    for (int i = 0; i < TRACE_MUDULE_SIZE; i++)
    {
        if (!strcmp(traced_modules[i], modulename))
        {
            return i;
        }
    }
    return -1;
}

int gettimenow(struct timeval *tv)
{
#ifdef WIN32
    struct timeb tb;
    ftime(&tb);
    (tv)->tv_sec = tb.time;
    (tv)->tv_usec = (time_t)tb.millitm * 1000;
    return 0;
#else
    return (gettimeofday(tv, (struct timezone *) NULL));
#endif
}
int gettimenow(struct timeval *tv, struct tm *the_time)
{
    if (gettimenow(tv) > -1)
    {
        time_t tt = (time_t)tv->tv_sec;
        *the_time = *(localtime(&tt));
        return 0;
    }
    else
    {
        return -1;
    }
}
int gettimenow_ms(time_t* ret)
{
    struct timeval now;
    if (gettimenow(&now) > -1)
    {
        event_logii(loglvl_extevent, "Time now: %ld sec, %ld usec \n", now.tv_sec,
            now.tv_usec);
        *ret = ((time_t)now.tv_sec) * 1000 + ((time_t)now.tv_usec) / 1000;
        return 0;
    }
    else
    {
        return -1;
    }
}
int gettimenow_us(time_t* ret)
{
    struct timeval now;
    if (gettimenow(&now) > -1)
    {
        event_logii(loglvl_extevent, "Time now: %ld sec, %ld usec \n", now.tv_sec,
            now.tv_usec);
        *ret = ((time_t)now.tv_sec) * 1000000 + (time_t)now.tv_usec;
        return 0;
    }
    else
    {
        return -1;
    }
}


void  sum_time(timeval* a, timeval* b, timeval* result)
{

    result->tv_sec = (a)->tv_sec + (b)->tv_sec;
    result->tv_usec = (a)->tv_usec + (b)->tv_usec;
    if (result->tv_usec >= 1000000)
    {
        ++result->tv_sec;
        result->tv_usec -= 1000000;
    }
}
void subtract_time(timeval* a, timeval* b, timeval* result)
{
    result->tv_sec = (a)->tv_sec - (b)->tv_sec;
    result->tv_usec = (a)->tv_usec - (b)->tv_usec;
    if (result->tv_usec < 0)
    {
        --result->tv_sec;
        result->tv_usec += 1000000;
    }
}

int subtract_time(timeval* a, timeval* b)
{
    struct timeval result;
    /* result = a-b */
    subtract_time(a, b, &result);
    int retval = result.tv_sec * 1000 + result.tv_usec / 1000;
    event_logi(verbose, "Computed Time Difference : %d msecs\n", retval);
    return ((retval < 0) ? -1 : retval);
}

void  sum_time(timeval* a, time_t inteval, timeval* result)
{
    timeval tv;
    fills_timeval(&tv, inteval);
    sum_time(a, &tv, result);
}
void subtract_time(timeval* a, time_t inteval, timeval* result)
{
    timeval tv;
    fills_timeval(&tv, inteval);
    subtract_time(a, &tv, result);
}
void subtract_time(timeval* a, time_t* inteval, timeval* result);
void print_time_now(ushort level)
{
    struct timeval now;
    gettimenow(&now);
    event_logii(level, "Time now: %ld sec, %ld usec \n", now.tv_sec,
        now.tv_usec);
}
void print_timeval(timeval* tv)
{
    event_logii(loglvl_intevent, "timeval {%ld, %ld}\n", tv->tv_sec, tv->tv_usec);
}

static int debug_vwrite(FILE* fd, const char* formate, va_list ap)
{
    struct timeval tv; // this is used for get usec
    struct tm the_time; // only contains data infos, no ms and us
    if (!gettimenow(&tv, &the_time))
    {
        // write fixed log header
        if (fprintf(fd, "%02d:%02d:%02d.%03d - ", the_time.tm_hour,
            the_time.tm_min, the_time.tm_sec, (int)(tv.tv_usec / 1000))
            < 1) // change to  ms
            return -1;
        // then write log msg
        if (vfprintf(fd, formate, ap) < 1)
            return -1;
        return 0;
    }
    else
    {
        return -1;
    }
}
void debug_print(FILE * fd, const char *f, ...)
{
    va_list va;
    va_start(va, f);
    debug_vwrite(fd, f, va);
    va_end(va);
    fflush(fd);
}

extern void event_log1(short event_log_level, const char *module_name,
    const char *log_info, ...)
{
    int mi;
    struct timeval  tv;
    struct tm  the_time;

    va_list va;
    va_start(va, log_info);
    bool f1 = globalTrace == true && event_log_level <= current_event_loglvl;
    int moduleindex = is_module_traced(module_name);
    bool f2 = globalTrace == false && moduleindex > 0
        && event_log_level <= event_trace_levels[moduleindex];
    if (f1 || f2)
    {
        if (event_log_level < verbose)
        {
            if (fileTrace == true)
            {
                debug_print(logfile, "Event in Module: %s............\n",
                    module_name);
            }
            else
            {
                debug_print(stdout, "Event in Module: %s............\n",
                    module_name);
            }
        }
        gettimenow(&tv, &the_time);
        if (fileTrace == true)
        {
            fprintf(logfile, "%02d:%02d:%02d.%03d - ",
                the_time.tm_hour,
                the_time.tm_min,
                the_time.tm_sec,
                (int)(tv.tv_usec / 1000));
            vfprintf(logfile, log_info, va);
            fprintf(logfile, "\n");
            fflush(logfile);
        }
        else
        {
            fprintf(stdout, "%02d:%02d:%02d.%03d - ",
                the_time.tm_hour,
                the_time.tm_min,
                the_time.tm_sec,
                (int)(tv.tv_usec / 1000));
            vfprintf(stdout, log_info, va);
            fprintf(stdout, "\n");
            fflush(stdout);
        }
    }
    va_end(va);
}
extern void error_log1(short error_loglvl, const char *module_name, int line_no,
    const char *log_info, ...)
{
    int mi;
    va_list va;

    va_start(va, log_info);
    bool f1 = globalTrace == true && error_loglvl <= current_event_loglvl;
    int moduleindex = is_module_traced(module_name);
    bool f2 = globalTrace == false && moduleindex > 0
        && error_loglvl <= event_trace_levels[moduleindex];
    if (f1 || f2)
    {
        if (fileTrace == true)
        {
            debug_print(logfile,
                "Error[%2d,%s] in %s at line %d\n",
                error_loglvl, error_loglvls_str[error_loglvl - 1], module_name, line_no);
            /*   fprintf(logfile, "Error Info: ");*/
            vfprintf(logfile, log_info, va);
            fprintf(logfile, "\n");
        }
        else
        {
            debug_print(stderr,
                "Error[%2d,%s] in %s at line %d, ",
                error_loglvl, error_loglvls_str[error_loglvl - 1], module_name, line_no);
            /*   fprintf(logfile, "Error Info: ");*/
            vfprintf(stderr, log_info, va);
            fprintf(stderr, "\n");
        }
    }
    va_end(va);

    if (fileTrace == true)
    {
        fflush(logfile);
    }
    else
    {
        fflush(stderr);
    }
    if (error_loglvl == loglvl_fatal_error_exit)
    {
        char str[32];
        sprintf(str, "%s exits at line %d", module_name, line_no);
        perr_exit(str);
    }
    if (error_loglvl == major_error_abort)
    {
        char str[32];
        sprintf(str, "%s aborts at line %d", module_name, line_no);
        perr_abort(str);
    }
}
void error_log_sys1(short error_log_level, const char *module_name, int line_no,
    short errnumber)
{
    error_log1(error_log_level, module_name, line_no, strerror(errnumber));
}

void perr_exit(const char *infostring)
{
    perror(infostring);
    exit(1);
    abort();
}
void perr_abort(const char *infostring)
{
    perror(infostring);
    abort();
}
//++++++++++++++++++ helpers +++++++++++++++
bool safe_before(uint seq1, uint seq2)
{
    // INT32_MAX = (2147483647)
    // INT32_MIN = (-2147483647-1)
    // UINT32_MAX = 4294967295U
    // assume a extream situation where seq1 = 0, seq2 = UINT32_MAX,
    // seq1 - seq2 = -4294967295 ���int��ʵ��ֵ���� (int) ��-1�� ��Ϊ
    // INT32_MAX-INT32_MIN ����UINT32_MAX���պ������int�ĸ�ֵ����
    // Ҳ����С��0�� �������ǵ���Ҫ
    // ʵ�������ǻ����Է���һ���ȱȽϵ����͸�������ͣ���֯�������Ĳ���
    // ����   return (uint64) (seq1 - seq2) < 0;
    return ((int)(seq1 - seq2)) < 0;
}
bool safe_after(uint seq1, uint seq2)
{
    return ((int)(seq2 - seq1)) < 0;
}
bool safe_before(ushort seq1, ushort seq2)
{
    return ((short)(seq1 - seq2)) < 0;
}
bool safe_after(ushort seq1, ushort seq2)
{
    return ((short)(seq2 - seq1)) < 0;
}
// if s1 <= s2 <= s3
// @pre seq1 <= seq3
bool safe_between(uint seq1, uint seq2, uint seq3)
{
    return safe_before(seq1, seq3) ?
        seq3 - seq1 >= seq2 - seq1 : seq3 - seq1 <= seq2 - seq1;
}
// @pre make sure seq1 <= seq3
bool unsafe_between(uint seq1, uint seq2, uint seq3)
{
    return seq3 - seq1 >= seq2 - seq1;
}
/**
 * helper function for sorting list of chunks in tsn order
 * @param  one pointer to chunk data
 * @param  two pointer to other chunk data
 * @return 0 if chunks have equal tsn, -1 if tsn1 < tsn2, 1 if tsn1 > tsn2
 */
int sort_tsn(const internal_data_chunk_t& one,
    const internal_data_chunk_t& two)
{
    if (safe_before(one.chunk_tsn, two.chunk_tsn))
        return -1;
    else if (safe_after(one.chunk_tsn, two.chunk_tsn))
        return 1;
    else
        return 0; /* one==two */
}
int sort_ssn(const internal_stream_data_t& one,
    const internal_stream_data_t& two)
{
    if (one.stream_id < two.stream_id)
    {
        return -1;
    }
    else if (one.stream_id > two.stream_id)
    {
        return 1;
    }
    else /* one.sid==two.sid */
    {
        if (safe_before(one.stream_sn, two.stream_sn))
            return -1;
        else if (safe_after(one.stream_sn, two.stream_sn))
            return 1;
    }
    return 0;
}

uint get_random()
{
    //// create default engine as source of randomness
    //std::default_random_engine dre;
    //// use engine to generate integral numbers between 10 and 20 (both included)
    //const  int maxx = std::numeric_limits<int>::max();
    //std::uniform_int_distribution<int> di(10, 20);
    //return 0;
    return (unsigned int)rand();
}


#define BASE 65521L             /* largest prime smaller than 65536 */
#define NMAX 5552
#define NMIN 16

/* Example of the crc table file */
#define CRC32C(c,d) (c=(c>>8)^crc_c[(c^(d))&0xFF])
static uint crc_c[256] =
{
    0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
    0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
    0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
    0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
    0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
    0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
    0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
    0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
    0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
    0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
    0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
    0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
    0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
    0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
    0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
    0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
    0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
    0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
    0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
    0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
    0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
    0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
    0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
    0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
    0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
    0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
    0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
    0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
    0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
    0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
    0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
    0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
    0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
    0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
    0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
    0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
    0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
    0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
    0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
    0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
    0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
    0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
    0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
    0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
    0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
    0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
    0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
    0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
    0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
    0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
    0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
    0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
    0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
    0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
    0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
    0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
    0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
    0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
    0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
    0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
    0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
    0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
    0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
    0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351,
};
static uint generate_crc32c(char *buffer, int length)
{
    unsigned char byte0, byte1, byte2, byte3, swap;
    uint      crc32 = ~0L;
    int           i;

    for (i = 0; i < length; i++)
    {
        CRC32C(crc32, buffer[i]);
    }
    crc32 = ~crc32;
    /* do the swap */
    byte0 = (unsigned char)crc32 & 0xff;
    byte1 = (unsigned char)(crc32 >> 8) & 0xff;
    byte2 = (unsigned char)(crc32 >> 16) & 0xff;
    byte3 = (unsigned char)(crc32 >> 24) & 0xff;
    swap = byte0; byte0 = byte3; byte3 = swap;
    swap = byte1; byte1 = byte2; byte2 = swap;
    crc32 = ((byte3 << 24) | (byte2 << 16) | (byte1 << 8) | byte0);

    return crc32;

}

int validate_crc32_checksum(char *buffer, int length)
{
    dctp_packet_t *message;
    uint      original_crc32;
    uint      crc32 = ~0;

    /* save and zero checksum */
    message = (dctp_packet_t *)buffer;
    original_crc32 = ntohl(message->pk_comm_hdr.checksum);
    event_logi(verbose, "DEBUG Validation : old crc32c == %x", original_crc32);
    message->pk_comm_hdr.checksum = 0;
    crc32 = generate_crc32c(buffer, length);
    event_logi(verbose, "DEBUG Validation : my crc32c == %x", crc32);

    return ((original_crc32 == crc32) ? 1 : 0);
}
int set_crc32_checksum(char *buffer, int length)
{
    dctp_packet_t *message;
    uint      crc32c;

    /* check packet length */
    if (length > NMAX || length < NMIN)
        return -1;

    message = (dctp_packet_t *)buffer;
    message->pk_comm_hdr.checksum = 0L;
    crc32c = generate_crc32c(buffer, length);
    message->pk_comm_hdr.checksum = htonl(crc32c);
    return 0;
}
uchar* key_operation(int operation_code)
{
    static uchar *secret_key = NULL;
    uint              count = 0, tmp;

    if (operation_code == KEY_READ) return secret_key;
    else if (operation_code == KEY_INIT)
    {
        if (secret_key != NULL)
        {
            error_log(loglvl_fatal_error_exit, "tried to init secret key, but key already created !");
            return secret_key;
        }
        secret_key = (unsigned char*)malloc(SECRET_KEYSIZE);
        while (count < SECRET_KEYSIZE)
        {
            /* if you care for security, you need to use a cryptographically secure PRNG */
            tmp = get_random();
            memcpy(&secret_key[count], &tmp, sizeof(uint));
            count += sizeof(uint);
        }
    }
    else
    {
        error_log(loglvl_fatal_error_exit, "unknown key operation code !");
        return NULL;
    }
    return secret_key;
}

char* Bitify(size_t mWritePosBits, char* mBuffer)
{
    static char out[1024 * 1024];

    if (mWritePosBits <= 0)
    {
        strcpy(out, "no bits to print\n");
        return;
    }
    int strIndex = 0;
    int inner;
    int stopPos;
    int outter;
    int len = BITS_TO_BYTES(mWritePosBits);

    for (outter = 0; outter < len; outter++)
    {
        if (outter == len - 1)
            stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
        else
            stopPos = 0;

        for (inner = 7; inner >= stopPos; inner--)
        {
            if ((mBuffer[outter] >> inner) & 1)
                out[strIndex++] = '1';
            else
                out[strIndex++] = '0';
        }
        out[strIndex++] = '\n';
    }

    out[strIndex++] = '\n';
    out[strIndex++] = 0;

    return out;
}
void Bitify(char* out, size_t mWritePosBits, char* mBuffer)
{
    if (mWritePosBits <= 0)
    {
        strcpy(out, "no bits to print\n");
        return;
    }
    int strIndex = 0;
    int inner;
    int stopPos;
    int outter;
    int len = BITS_TO_BYTES(mWritePosBits);

    for (outter = 0; outter < len; outter++)
    {
        if (outter == len - 1)
            stopPos = 8 - (((mWritePosBits - 1) & 7) + 1);
        else
            stopPos = 0;

        for (inner = 7; inner >= stopPos; inner--)
        {
            if ((mBuffer[outter] >> inner) & 1)
                out[strIndex++] = '1';
            else
                out[strIndex++] = '0';
        }
        out[strIndex++] = '\n';
    }

    out[strIndex++] = '\n';
    out[strIndex++] = 0;

}
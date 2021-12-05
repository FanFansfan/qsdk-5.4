/* @File:   qca-son-mem-debug.c
 * @Notes:  This C file has definition of Memory management debug APIs that implements
 *          abstraction of standard library memory management function calls
 *          and perform tracking of dynamic memory allocation
 *          These API's can be invoked in other SON applications to enable tracking
 *
 * Copyright (c) 2020 Qualcomm Technologies, Inc.
 *
 * All Rights Reserved.
 * Confidential and Proprietary - Qualcomm Technologies, Inc.
 *
 */

#include "common-lib.h"
#include "qca-son-mem-debug.h"
#include "filter-mgmt.h"
#include "memory-mgmt.h"

// Global Variables
char procname[OUTPUT_FILE_NAME_LEN];    // wsplcd-lan, wsplcd-guest, hyd-lan, hyd-guest...

pid_t processid;                        // Stores Process ID of this process
uint8_t g_mem_dbg_enable;               // Configure from SON application : flag to enable this memory debug feature
uint8_t g_onlyAudit;                    // Configure from SON application: flag to enable Only Auditing with minimal tracking info (only memory pointer, size)
                                        // (contd.) Otherwise store detailed information (allocate function name, line, size, memory pointer, allocation time, module and submodule information, category info)
uint8_t g_initialized;                  // Flag to store the initialization-complete for the first time
uint8_t g_enableloggingtofile;          // Configure from SON application : flag to enable writing log files to files int /tmp/sonmem-<process_name>-<process_id>.txt
uint32_t app_peak_allocation;           // This stores the peak memory allocation since started running of this application
uint32_t g_disabled_module;             // Configure from SON application : stores the modules that are disabled from memory tracking
const char *son_module_name[] = {
    "WSPLCD",               "LIBSTORAGE",           "LIBHYFICOMMON",        "LIBWPA2",              "LIBIEEE1905",          "LIBWIFISONCFG",
    "LIBHYFI_BRIDGE",       "HYD_CORE",             "HYD_HYCTL",            "HYD_MANAGERS_MC",      "HYD_MANAGERS_PLC",     "HYD_MANAGERS_WLAN",
    "HYD_MCFWDTBL_WLAN2G",  "HYD_MCFWDTBL_WLAN5G",  "HYD_MCFWDTBL_WLAN6G",  "HYD_PC_SERVICE",       "HYD_PS_SERVICE",       "HYD_PCW_SERVICE",
    "HYD_PCE_SERVICE",      "HYD_PCP_SERVICE",      "HYD_HE_SERVICE",       "HYD_IEEE1905_SERVICE", "HYD_TDSERVICE",        "HYD_LOGSERVICE",
    "HYD_WLB_BANDMONMBSA",  "HYD_WLB_MONITOR",      "HYD_WLB_STEERALGMBSA", "HYD_WLB_STEERMSG",     "HYD_WLB_WLANIF_MBSA",  "LBD_CORE",
    "LBD_BANDMON",          "LBD_DIAGLOG",          "LBD_ESTIMATOR",        "LBD_PERSIST",          "LBD_STADB",            "LBD_STEERALG",
    "LBD_STEEREXEC",        "LBD_WLANIF_ATH10K",    "LBD_WLANIF",           "QCA_PLC_SON",          "QCA_MAP_SERVICE",      "QCA_NON_SON"};

FILE *wp, *dbg_op, *graph_op;

// External Variables
extern filter_config_e g_blackorwhitelist;
extern son_mem_summary_t g_mem_summary[];
extern list_data_t *g_list_data;        // contains accepted/ignored function names
extern list_memory_t *g_list_mem;
extern uint32_t list_data_count;

#ifdef SON_MEM_DEBUG_FREE
extern uint32_t g_max_free_track;       // Configure from SON application : This stores maximum entries that can be stored in freed list (to save memory usage)
#endif

extern void display_struct_size_info();

void find_process_config_type();
void initialize_logging(uint8_t WriteLogToFile);
void initialize_filter_management(uint8_t EnableFilter, FILE *list_file );
void print_auditonly_header();

// SON CLI Global variable
int g_port_num;

// SON CLI Function prototypes
void initialize_soncli_interface();
int initialize_soncli_socket_interface(struct sockaddr_in *cliaddr);
int initialize_memdbg_socket_interface();
int receive_request_from_soncli(int sockfd);
void send_read_trigger_to_soncli(int sockfd, struct sockaddr_in *cliaddr, char *logfile);
void soncli_socket_interface_thread(void *arg);
static void son_cli_sock_cb();
static void son_mem_dbg_write_meminfo(FILE *write_file);

/**
 * @brief Initialization function - to be called from SON modules (wsplcd, hyd...),
 *        in-order to configure this son memory debug library
 *
 * @param [in] EnableFeature - flag to enable this memory debug feature
 * @param [in] OnlyAuditing - flag to enable Only Auditing with minimal tracking information (only memory pointer, size)
 * @param [in] Disable_Module - stores the module information that are disabled from memory tracking
 * @param [in] max_free_track
 * @param [in] WriteLogToFile
 * @param [in] EnableFilter
 * @param [in] list_file
 * @param [out] None
 *
 * @return Nothing (void)
 */
void son_initialize_mem_debug(uint8_t EnableFeature, uint8_t OnlyAuditing, uint64_t Disable_Module, uint32_t max_free_track, uint8_t WriteLogToFile,  uint8_t EnableFilter, FILE *list_file )
{
    printf("[%s]: EnableFeature[%d] OnlyAuditing[%d] Disable_Module[%llu] max_free_track[%d] WriteLogToFile[%d] EnableFilter[%d] \n",
            __func__, EnableFeature, OnlyAuditing, (long long unsigned int)Disable_Module, max_free_track, WriteLogToFile, EnableFilter );
    g_mem_dbg_enable = EnableFeature;

    if (!CHECK_BIT_ENABLED(g_mem_dbg_enable, ENABLE_FEATURE)) {
        return;
    }
    if (Disable_Module) {
        g_disabled_module = Disable_Module;
    }
    if (OnlyAuditing) {
        g_onlyAudit = OnlyAuditing;
    }

    processid = getpid();
    find_process_config_type();

    if (g_initialized && WriteLogToFile ) {
        initialize_logging(WriteLogToFile);
    }
    // Establish Socket communication with SON-CLI
    if (g_initialized) {
        initialize_soncli_interface();
    }
    if (!OnlyAuditing && (EnableFilter != FILTER_NOT_SET)) {
        initialize_filter_management(EnableFilter, list_file);
    }
#ifdef SON_MEM_DEBUG_FREE
    if (max_free_track) {
        g_max_free_track = max_free_track;
    }
#endif
    display_struct_size_info();
    print_mem_info(wp,"[PID:%d][Configuration Settings]:\nEnableMemoryDebug:[%d]\nOnly Auditing:[%d]\nDisable Module:[%llu]\nMax Freed mem tracking:[%d]\nWriteLogToFile:[%d]\nEnable Filter:[%d]\n", processid, EnableFeature, OnlyAuditing, (long long unsigned int)Disable_Module, max_free_track, WriteLogToFile, EnableFilter);
    print_mem_info(wp, "Filter configuration memory usage: %zu total_count [%d]\n", (list_data_count * sizeof (list_data_t)), list_data_count);

    if (g_list_data) {
        display_filter_function_list();
    }

    if (g_onlyAudit) {
        print_auditonly_header();
    }

    return;
}

/*
 * Find process name (wsplcd|hyd|lbd) and config type (lan|guest)
 * from process information in /proc/self/cmdline file
 */
void find_process_config_type()
{
    int nread = 0, movedist = 0;
    char *ptr, *eptr, *loc;
    char cmd_line[PROC_CMD_LINE_DATA_LEN+1];
    char proc_cmd_line[PROC_CMD_LINE_FILE_LEN];
    FILE *fp;

    snprintf(proc_cmd_line, PROC_CMD_LINE_FILE_LEN, "/proc/%d/cmdline",processid);
    debug_printf("process: %s\n\n", proc_cmd_line);

    fp = fopen(proc_cmd_line, "r");
    if (fp != NULL) {
        if ( (nread = fread(cmd_line, 1, PROC_CMD_LINE_DATA_LEN, fp)) > 0) {
            cmd_line[nread] = '\0';
            debug_printf("proc cmdline: %s nread[%d]\n", cmd_line, nread);
            loc = cmd_line;
            while(nread > 0 && g_initialized == 0 ) {
                movedist = 0;
                if ((ptr = strstr(loc, "/tmp/")) != NULL) {
                    ptr+= strlen("/tmp/");
                    if ((eptr = strstr(ptr, ".conf")) != NULL) {
                        strlcpy(procname, ptr, eptr-ptr+1);
                        g_initialized = 1;
                    }
                }
                movedist += strlen(loc);
                movedist++;
                loc += movedist;
                nread -= movedist;
            }
        }
        fclose(fp);
    }
}

/*
 * Initialize file pointers for logging purpose
 * Filename syntax: /tmp/sonmeminfo-<wsplcd|hyd|lan>-<lan|guest>-<process_id>.txt
 * Use stdout if opening the file in tmp location failed
 */
void initialize_logging(uint8_t WriteLogToFile)
{
    char logfilename[OUTPUT_FILE_NAME_LEN];
    char dbgfilename[OUTPUT_FILE_NAME_LEN];
    char graphfilename[OUTPUT_FILE_NAME_LEN];

    g_enableloggingtofile = WriteLogToFile;
    memset( logfilename, 0, OUTPUT_FILE_NAME_LEN);
    memset( dbgfilename, 0, OUTPUT_FILE_NAME_LEN);
    memset( graphfilename, 0, OUTPUT_FILE_NAME_LEN);

    snprintf(logfilename, OUTPUT_FILE_NAME_LEN, "%s-%s-%d.txt",INFO_TMP_DIR, procname, processid);
    snprintf(dbgfilename, OUTPUT_FILE_NAME_LEN, "%s-%s-%d.txt",DBG_TMP_DIR, procname, processid);
    snprintf(graphfilename, OUTPUT_FILE_NAME_LEN, "%s-%s-%d.txt",GRAPH_TMP_DIR, procname, processid);
    printf("Generated memory debug output filename : %s\n", logfilename);

    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_MEMINFO)) {
        wp = fopen(logfilename, "w");
        if (wp == NULL) {
            printf("Unable to open file [%s]! Using stdout for info output !!!\n", logfilename);
            wp = stdout;
        }
    }
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_DBG_OUTPUT)) {
        dbg_op = fopen(dbgfilename, "w");
        if (dbg_op == NULL) {
            printf("Unable to open file [%s]! Using stdout for dbg output !!!\n", dbgfilename);
            dbg_op = stdout;
        }
    }
    if (CHECK_BIT_ENABLED(g_enableloggingtofile, REPORT_GRAPH)) {
        graph_op = fopen(graphfilename, "w");
        if (graph_op == NULL) {
             printf("Unable to open file [%s]! Using stdout for graph output !!!\n", graphfilename);
            graph_op = stdout;
        }
    }
}

/*
 * Initialize filter management module
 * Create list with function names to be filtered
 */
void initialize_filter_management(uint8_t EnableFilter, FILE *list_file )
{
    if (list_file != NULL) {
        if (create_filter_list(list_file) == ENTRY_ADD_SUCCESS) {
            printf("Filter List created... \n");
        }
        else {
            print_mem_info(wp, "Unable to create filter list (file open/mem failure) ... \n");
        }
        g_blackorwhitelist = EnableFilter;
    }
    else {
        print_mem_info(wp, "Filter Enabled, But Filter data file not specified... \n");
    }
    fflush(wp);
}

/*
 * Print Configuration supplied from SON application
 * and display memory information header for audit only output
 */
void print_auditonly_header()
{
    print_mem_info(wp, "Memory Usage Information (Audit Only Output: SON Application + Libraries Mem Usage)\n");
    print_mem_info(wp, "===================================================================================\n");
    print_mem_info(wp, "%-14s%-14s%-14s%-14s%-9s%-9s%-9s%-9s%-9s%-9s\n", "Alloc_count", "Mem_Usage", "MemToolUsage", "Total" , "VmPeak", "VmSize", "VmHWM", "VmRSS", "VmData", "VmStk");
    fflush(wp);
}


int soncli_pthread_create( pthread_t *thread, void * (*thread_cb)(void *data), void *arg )
{
    pthread_attr_t custom_sched_attr;
    struct sched_param param;
    int min_prio;
    int ret=0;

    pthread_attr_init(&custom_sched_attr);
    pthread_attr_setinheritsched(&custom_sched_attr, PTHREAD_EXPLICIT_SCHED);
    pthread_attr_setschedpolicy(&custom_sched_attr, SCHED_RR);
    min_prio = sched_get_priority_min(SCHED_RR);
    param.sched_priority = min_prio;
    pthread_attr_setschedparam(&custom_sched_attr, &param);
    ret = pthread_create( thread, NULL, thread_cb, arg);
    return ret;
}

int initialize_soncli_socket_interface(struct sockaddr_in *cliaddr)
{
    int sockfd = 0;
    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(cliaddr, 0, sizeof(struct sockaddr_in));

    cliaddr->sin_family    = AF_INET; // IPv4
    cliaddr->sin_addr.s_addr = INADDR_ANY;
    cliaddr->sin_port = htons(SON_CLI_PORT);

    return sockfd;
}

int initialize_memdbg_socket_interface()
{
    int sockfd = 0;

    struct sockaddr_in servaddr;

    // Creating socket file descriptor
    if ( (sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&servaddr, 0, sizeof(servaddr));

    // Filling server information
    servaddr.sin_family    = AF_INET; // IPv4
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(g_port_num);

    // Bind the socket with the server address
    if ( bind(sockfd, (const struct sockaddr *)&servaddr,
            sizeof(servaddr)) < 0 )
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
    return sockfd;
}

int receive_request_from_soncli(int sockfd)
{
    char buffer[SOCK_DATA_MAX_LINE];
    struct sockaddr_in cliaddr;
    socklen_t len = 0;
    int data = 0;

    memset(&cliaddr, 0, sizeof(cliaddr));
    memset(buffer, 0, SOCK_DATA_MAX_LINE);

    data = recvfrom(sockfd, buffer, SOCK_DATA_MAX_LINE,
        MSG_WAITALL, (struct sockaddr*) &cliaddr, &len );

    if (data > 0)
    {
        buffer[data] = '\0';
        debug_printf("memlib:Received from client : %s\n", buffer);
    } else {
        debug_printf("memlib: Error: Received failed !!!\n");
    }


    return 0;
}

void send_read_trigger_to_soncli(int sockfd, struct sockaddr_in *cliaddr, char *logfile)
{
    int ret = 0;

    if (!strlen(logfile)) {
        printf("%s: sendto failed!!!\n", __func__);
        return;
    }
    debug_printf("memlib:%s...%d\n",__func__, __LINE__);
    ret = sendto(sockfd, (const char *)logfile, OUTPUT_FILE_NAME_LEN,
        MSG_CONFIRM, (const struct sockaddr *) cliaddr, sizeof(*cliaddr));

    debug_printf("memlib:%s...%d\n",__func__, __LINE__);
    if (ret < 0) {
        printf("%s: sendto failed!!!\n", __func__);
    }

    return;
}

/*
 * Write Memory usage information to file
 */
static void son_cli_sock_cb (char *logfile)
{
    uint8_t write_log_to_file;
    FILE *write_ptr = NULL;

    write_log_to_file = g_enableloggingtofile;
    g_enableloggingtofile = 1;

    snprintf(logfile, OUTPUT_FILE_NAME_LEN, "%s-%s.txt",INFO_TMP_DIR, procname);

    debug_printf("Log filename :%s\n", logfile );

    // write the memory info to file
    write_ptr = fopen(logfile, "w");
    if (write_ptr != NULL) {
        son_mem_dbg_write_meminfo(write_ptr);
        fclose(write_ptr);
    }
    // Restore original config
    g_enableloggingtofile = write_log_to_file;
}

/*
 * Create and Establish socket link with SON application
 */
void soncli_socket_interface_thread(void *arg)
{
    char logfile[OUTPUT_FILE_NAME_LEN];
    struct sockaddr_in cliaddr;
    int soncli_sock = 0, memdbg_sock = 0;

    memset(logfile, 0, OUTPUT_FILE_NAME_LEN);
    memset(&cliaddr, 0, sizeof(cliaddr));

    memdbg_sock = initialize_memdbg_socket_interface();   // receive from soncli

    // Initialize soncli socket communication parameters
    soncli_sock = initialize_soncli_socket_interface(&cliaddr); // send to soncli

    for(;;)
    {
        // Receive Memory info request from SON CLI
        receive_request_from_soncli(memdbg_sock);

        // Write the memory info to a file
        son_cli_sock_cb(logfile);

        // Send trigger to SON CLI to read the memory information from file
        send_read_trigger_to_soncli(soncli_sock, &cliaddr, logfile);

    }
}

/*
 * Initialize UDP socket communication to SON CLI module
 * Find the port number based on application name and type
 */
void initialize_soncli_interface()
{
    int ret = 0;
    pthread_t memdbg_th = 0;

    if (strcmp(procname, "hyd-lan") == 0 || strcmp(procname, "hyd") == 0)
        g_port_num = SON_CLI_HYD_LAN_PORT;
    else if (strcmp(procname, "hyd-Guest") == 0 || strcmp(procname, "hyd-guest") == 0)
        g_port_num = SON_CLI_HYD_GUEST_PORT;
    else if (strcmp(procname, "wsplcd-lan") == 0 || strcmp(procname, "wsplcd") == 0)
        g_port_num = SON_CLI_WSPLCD_LAN_PORT;
    else if (strcmp(procname, "wsplcd-Guest") == 0 || strcmp(procname, "wsplcd-guest") == 0)
        g_port_num = SON_CLI_WSPLCD_GUEST_PORT;
    else if (strcmp(procname, "lbd") == 0)
        g_port_num = SON_CLI_LBD_PORT;

    debug_printf("Port number selected based on config file name: Config Name[%s], Port Number[%d]\n", procname, g_port_num);

    ret = soncli_pthread_create(&memdbg_th, (void*)soncli_socket_interface_thread, NULL);
    if (ret != 0) {
        printf("%s: Error: soncli_pthread_create failed [%d]!!!\n", __func__, ret);
    }
    else {
        debug_printf("thread created !!!\n");
    }
}

uint32_t check_module_enabled_for_tracking(son_module_e mod)
{
    uint32_t ret = 0;   // return 0 if module is enabled for detailed info tracking
    if ( g_disabled_module & (1<<mod)) {
        ret = -1;  // module disabled
    }
    return ret;
}

void *son_malloc_mem_debug(size_t size, son_mem_dbg_data_t *dbg_data)
{
    void *ptr = NULL;
    ptr = malloc(size);
    son_memory_debug(ptr, size, dbg_data->func, dbg_data->line, dbg_data->mod, dbg_data->cat, dbg_data->cdata );
    return ptr;
}

void* son_malloc_debug(size_t size, const char *func, uint32_t line , son_module_e mod, son_mem_category_e cat, void *cdata )
{
    void *ptr = NULL;
    ptr = malloc(size);
    son_memory_debug(ptr, size, func, line, mod, cat, cdata );
    return ptr;
}

void* son_calloc_debug(size_t nmemb, size_t size, const char *func, uint32_t line ,
        son_module_e mod, son_mem_category_e cat, void *cdata )
{
    void *ptr = NULL;
    ptr = calloc(nmemb, size);
    son_memory_debug(ptr, nmemb*size, func , line, mod, cat, cdata );
    return ptr;
}

void* son_realloc_debug(void *oldptr, size_t newsize, const char *func, uint32_t line ,
        son_module_e mod, son_mem_category_e cat, void *cdata )
{
    void *newptr = NULL;
    newptr = realloc(oldptr, newsize);

    if (!CHECK_BIT_ENABLED(g_mem_dbg_enable, ENABLE_FEATURE)) {
        return newptr;
    }

    if (newptr == NULL) {
        print_mem_info(wp, "[%s]: SON-MEM-ERR: REALLOC failure ptr[%p] realloc_func[%s] line[%d]!!!\n", __func__, newptr, func, line);
        return newptr;
    }

    dbg_print(dbg_op, "[%s]: SON-MEM-DBG: module[%s] oldptr[%p] newptr[%p] realloc_func[%s] free_line[%u]\n", __func__, son_module_name[mod], oldptr, newptr, func, line );
    fflush(dbg_op);
    if (oldptr == NULL) {        // this realloc() call is equivalent to malloc() call
        son_memory_debug(newptr, newsize, func, line, mod, cat, cdata);
    }
    else if ((oldptr != NULL) && (newsize == 0)) {    // this realloc() call is equivalent to free() call, just free the memory and return
        son_free_debug(oldptr, func, line, mod, 1 );
    }
    else if (oldptr == newptr) {        // Only update the new memory size
        if (find_and_update_mem_size(oldptr, newsize)) {
            dbg_print(dbg_op, "[%s]: SON-MEM-DBG: Allocation not found: module[%s] ptr[%p] realloc_func[%s] free_line[%u]\n", __func__, son_module_name[mod], newptr, func, line );
            g_mem_summary[mod].mem_realloc_mgmt_failure++;
        }
    }
    else if (oldptr != newptr) {        // add new entry into allocation list and free old pointer is freed
        son_free_debug(oldptr, func, line, mod, 1 );
        son_memory_debug(newptr, newsize, func, line, mod, cat, cdata );
    }

    return newptr;
}

void son_free_debug(void *ptr, const char *func, uint32_t line, son_module_e mod, uint8_t is_relloc)
{
    uint32_t notify_failure = 0, ret = ENTRY_NOT_FOUND;
    son_module_e alt_mod = QCA_MOD_WSPLCD;

    if (!is_relloc) {
        free(ptr);
    }

    if (!CHECK_BIT_ENABLED(g_mem_dbg_enable, ENABLE_FEATURE)) {
        return;
    }

    dbg_print(dbg_op, "[%s]: SON-MEM-DBG: module[%s] ptr[%p] free_func[%s] free_line[%u]\n", __func__, son_module_name[mod], ptr, func, line );
    fflush(dbg_op);

    if (!g_onlyAudit ) {
        if ((ret = son_mem_dbg_remove_entry_from_list( mod, ptr, func, line)) == ENTRY_REMOVE_SUCCESS) {   // first check in own module
            notify_failure = 0;
        } else {        // second check in other modules
            while (alt_mod < QCA_MOD_MAX) {
                if (mod == alt_mod) {
                    alt_mod++;
                    continue;
                }
                if ((ret = son_mem_dbg_remove_entry_from_list( alt_mod, ptr, func, line)) == ENTRY_REMOVE_SUCCESS) {
                    if ( mod == alt_mod ) {
                        dbg_print(dbg_op, "[%s]: SON-MEM-INFO: Allocation by another module : alloc[%s] free[%s]\n", __func__, son_module_name[alt_mod], son_module_name[mod]);
                    }
                    notify_failure = 0;
                    break;
                }
                alt_mod++;
            }
        }
    }
    if ((ret == ENTRY_NOT_FOUND) || g_onlyAudit || g_list_mem) {
        if ((ret = check_and_remove_from_filtered_list(ptr, mod)) == ENTRY_REMOVE_SUCCESS) {
            notify_failure = 0;
        }
    }
    if (notify_failure == 0) {
        g_mem_summary[mod].total_free_count++;
    }
    else {
        g_mem_summary[mod].mem_free_mgmt_failure++;
        print_mem_info(wp, "[%s]: SON-MEM-ERR: SON Memory Management FREE failure ptr[%p] free_func[%s] line[%d]!!!\n", __func__, ptr, func, line);
        fflush(dbg_op);
    }
}


char *son_strdup_debug(const char *oldptr, const char *func, uint32_t line, son_module_e mod, son_mem_category_e cat, void *cdata)
{
    size_t len=0;
    void *newptr = NULL;

    if (oldptr != NULL) {
        len = strlen(oldptr)+1;
        newptr = (void *) malloc(len);
        if (newptr != NULL) {
            strlcpy(newptr, oldptr, len);
            if (CHECK_BIT_ENABLED(g_mem_dbg_enable, ENABLE_FEATURE)) {
                dbg_print(dbg_op, "[%s]: SON-MEM-DBG: module[%s][%d] ptr[%p] strdup_func[%s] free_line[%u]\n", __func__, son_module_name[mod], mod, newptr, func, line );
                fflush(dbg_op);
                son_memory_debug(newptr, len, func, line, mod, cat, cdata );
            }
        }
    }
    return newptr;
}

void son_mem_dbg_write_meminfo(FILE *write_file)
{
    if (g_onlyAudit) {
        son_mem_dbg_display_minimal_list_info(write_file);
    }
    else {
        son_mem_dbg_display_detailed_list_info(write_file);
    }
}

void son_mem_dbg_display_list()
{
    if (g_onlyAudit) {
        son_mem_dbg_display_minimal_list_info(wp);
    }
    else {
        son_mem_dbg_display_detailed_list_info(wp);
    }
}

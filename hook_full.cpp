#include <jni.h>
#include <string>
#include <android/log.h>
#include <thread>
#include <unistd.h>
#include <link.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fstream>
#include <map>
#include <mutex>
#include "dobby.h"
#define TAG "HOOK"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define TARGET_SO "libnative-lib.so"

// ===== Core RVA =====
#define RVA_CELL_PARSE  0x94BBE0

// 🎯 Dump Output Directory
#define DUMP_DIR "/storage/emulated/0/Download/catdump/"

// Global State Matrix Protection
std::map<void*, int> g_reader_to_id;
int g_file_counter = 0;
std::mutex g_matrix_mutex;

// Scans and extracts Ponos custom std::string structures
std::string extract_ponos_string(void* string_ptr) {
    if (!string_ptr) return "";
    uint8_t* p = (uint8_t*)string_ptr;

    if ((p[0] & 1) == 0) { // Short String
        size_t len = p[0] >> 1;
        if (len > 0 && len < 64) return std::string((char*)(p + 1), len);
    } else { // Long String (Heap pointer at Word 2)
        uint64_t* words = (uint64_t*)string_ptr;
        uint64_t len = words[1];
        char* real_ptr = (char*)words[2];
        if (len > 0 && len < 102400 && real_ptr > (char*)0x100000000000 && real_ptr < (char*)0x7fffffffffff) {
            return std::string(real_ptr, len);
        }
    }
    return "";
}

// Core Interceptor for cell_parse
typedef void* (*cell_parse_t)(void* p1, void* p2, void* p3);
cell_parse_t orig_cell_parse = nullptr;

void* proxy_cell_parse(void* p1, void* p2, void* p3) {
    int col_idx = (int)(uintptr_t)p3;
    void* result = orig_cell_parse(p1, p2, p3);

    if (p1 && p2) {
        std::string cell_data = extract_ponos_string(p1);
        if (cell_data.empty()) cell_data = "0";

        // 👑 Thread-Local states to fully eliminate tail-end omission bugs
        thread_local void* tl_last_reader_obj = nullptr;
        thread_local std::string tl_row_buffer = "";
        thread_local int tl_current_file_id = -1;

        bool require_flush = false;
        int flush_target_id = -1;

        // 👑 Boundary Detection Engine
        if (p2 != tl_last_reader_obj) {
            // Condition 1: Reader instance changed -> A new file has loaded!
            // Force flush the trailing last row of the previous file immediately.
            require_flush = true;
            flush_target_id = tl_current_file_id;
        } else if (col_idx == 0) {
            // Condition 2: Same file, but a new row started. Flush completed previous row.
            require_flush = true;
            flush_target_id = tl_current_file_id;
        }

        // 🚀 Execute flush mechanism directly to absolute file path
        if (require_flush && flush_target_id != -1 && !tl_row_buffer.empty()) {
            std::lock_guard<std::mutex> lock(g_matrix_mutex);
            std::ofstream out_file;
            char full_path[128];
            snprintf(full_path, sizeof(full_path), "%sAsset_Table_%03d.csv", DUMP_DIR, flush_target_id);

            out_file.open(full_path, std::ios::app);
            if (out_file.is_open()) {
                out_file << tl_row_buffer << "\n";
                out_file.close();
            }
            tl_row_buffer = "";
        }

        // Initialize identifiers for the newly incoming context block
        if (p2 != tl_last_reader_obj) {
            std::lock_guard<std::mutex> lock(g_matrix_mutex);
            if (g_reader_to_id.find(p2) == g_reader_to_id.end()) {
                g_file_counter++;
                g_reader_to_id[p2] = g_file_counter;
                LOGD("[NEW_ASSET] Object: %p assigned to Asset_Table_%03d.csv", p2, g_file_counter);
            }
            tl_current_file_id = g_reader_to_id[p2];
            tl_last_reader_obj = p2;
            tl_row_buffer = cell_data;
        } else {
            if (col_idx == 0) {
                tl_row_buffer = cell_data;
            } else {
                tl_row_buffer += "," + cell_data;
            }
        }
    }
    return result;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("🚀 SkyNet Asset Recovery Engine Activated...");

    mkdir(DUMP_DIR, 0777);

    std::thread([]() {
        uintptr_t base = 0;
        while (base == 0) {
            struct { const char* n; uintptr_t b; } mi = {TARGET_SO, 0};
            dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) {
                auto m = (decltype(mi)*)data;
                if (info->dlpi_name && strstr(info->dlpi_name, m->n)) {
                    m->b = (uintptr_t)info->dlpi_addr; return 1;
                }
                return 0;
            }, &mi);
            base = mi.b;
            usleep(50000);
        }

        void* addr_parse = (void*)(base + RVA_CELL_PARSE);
        DobbyHook(addr_parse, (void*)proxy_cell_parse, (void**)&orig_cell_parse);

        LOGD("🛡️ SkyNet Array locked onto memory streams. Awaiting extraction telemetry...");
    }).detach();

    return JNI_VERSION_1_6;
}

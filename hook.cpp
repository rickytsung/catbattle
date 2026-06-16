#include <jni.h>
#include <string>
#include <android/log.h>
#include <thread>
#include <unistd.h>
#include <link.h>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <set>
#include <map>
#include <mutex>
#include "dobby.h"  // 👑 嚴格引入 dobby.h

#define TAG "HOOK"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define TARGET_SO "libnative-lib.so"

// ===== 經 Ghidra 虛擬碼驗證後的黃金雙 RVA =====
#define RVA_OPEN_FILE   0x8AB4A0  // FUN_009ab4a0
#define RVA_CELL_PARSE  0x94BBE0  // FUN_00a4bbe0

// 🎯 三個獨立實體路徑，直接存放於 Download 公共區
#define PATH_ALIGNED "/storage/emulated/0/Download/perfect_aligned_assets.txt"
#define PATH_UNIQUE  "/storage/emulated/0/Download/unique_filenames.txt"
#define PATH_RAW     "/storage/emulated/0/Download/raw_intercepted_data.txt"

std::ofstream file_aligned;
std::ofstream file_unique;
std::ofstream file_raw;

// 雙重保險狀態機：結合物件綁定與執行緒時序
std::map<void*, std::string> g_reader_obj_map; // 物件位址 -> 真實檔名
thread_local std::string tl_current_file_name = "Initial_Startup_Asset.csv";
thread_local void* tl_last_reader_obj = nullptr;
thread_local std::string tl_row_buffer = "";

// 👑 修正錯位的黃金變數：記住這一行「出生時」的舊名字
thread_local std::string tl_active_row_name = ""; 

std::set<std::string> g_unique_names;
std::mutex g_io_mutex;

// 檔名洗淨優化器
std::string get_clean_filename(const std::string& raw_name) {
    size_t start = 0;
    while (start < raw_name.length() && 
          (raw_name[start] == '(' || raw_name[start] == '*' || raw_name[start] == '$' || 
           raw_name[start] == '"' || raw_name[start] == '!' || raw_name[start] == '&' || 
           raw_name[start] == ',' || raw_name[start] == ' ')) {
        start++;
    }
    return raw_name.substr(start);
}

// 👑 完美破解 Ponos 記憶體結構：相容短字串與長字串 Heap 偏移
std::string extract_ponos_string(void* string_ptr) {
    if (!string_ptr) return "";
    uint8_t* p = (uint8_t*)string_ptr;
    
    if ((p[0] & 1) == 0) { // 短字串
        size_t len = p[0] >> 1;
        if (len > 0 && len < 23) {
            return std::string((char*)(p + 1), len);
        }
    } else { // 長字串
        uint64_t* words = (uint64_t*)string_ptr;
        uint64_t len = words[1];          
        char* real_ptr = (char*)words[2]; // 真正的 Heap 指標在 Word 2
        
        if (len > 0 && len < 102400 && real_ptr > (char*)0x100000000000 && real_ptr < (char*)0x7fffffffffff) {
            return std::string(real_ptr, len);
        }
    }
    return "";
}

// 1. 檔案開啟攔截器 (修復了將指標當成字串讀取而產生 "1" 的史詩級 Bug！)
typedef uint64_t (*open_file_t)(void* p1, void* p2, void* p3, void* p4);
open_file_t orig_open_file = nullptr;

uint64_t proxy_open_file(void* p1, void* p2, void* p3, void* p4) {
    uint64_t res = orig_open_file(p1, p2, p3, p4);
    
    if (p1 && p2) {
        // 👑 使用解碼器解析 p2，不再強制轉型 const char* 讀到記憶體垃圾
        std::string actual_name = extract_ponos_string(p2);
        
        if (!actual_name.empty()) {
            std::string clean_name = get_clean_filename(actual_name);
            std::lock_guard<std::mutex> lock(g_io_mutex);
            
            // 保險 1：寫入執行緒專屬時序
            tl_current_file_name = clean_name;
            
            // 保險 2：提取回傳的 CSVReader 實體物件指標，建立絕對鎖定
            void* reader_obj = *(void**)p1;
            if (reader_obj > (void*)0x100000000000) {
                g_reader_obj_map[reader_obj] = clean_name;
            }

            if (g_unique_names.find(clean_name) == g_unique_names.end()) {
                g_unique_names.insert(clean_name);
                if (file_unique.is_open()) {
                    file_unique << clean_name << "\n";
                    file_unique.flush();
                }
            }
        }
    }
    return res;
}

// 2. 單元格欄位解析攔截器 (0x94BBE0)
typedef void* (*cell_parse_t)(void* p1, void* p2, void* p3);
cell_parse_t orig_cell_parse = nullptr;

void* proxy_cell_parse(void* p1, void* p2, void* p3) {
    int col_idx = (int)(uintptr_t)p3;
    void* result = orig_cell_parse(p1, p2, p3);

    if (p1 && p2) {
        std::string cell_data = extract_ponos_string(p1);
        if (cell_data.empty()) cell_data = "0";

        std::lock_guard<std::mutex> lock(g_io_mutex);

        // 【通道三：原始流】無條件記錄所有資料
        if (file_raw.is_open()) {
            file_raw << "Reader:" << p2 << " | Col:" << col_idx << " | Data:" << cell_data << "\n";
            if (col_idx == 0) file_raw.flush();
        }

        // 優先從物件綁定地圖抓名字，抓不到再退回執行緒時序名字
        std::string final_name = tl_current_file_name;
        if (g_reader_obj_map.find(p2) != g_reader_obj_map.end()) {
            final_name = g_reader_obj_map[p2];
        }

        // 依據老哥的黃金規律：Reader 變更代表換檔案臨界點
        if (p2 != tl_last_reader_obj) {
            if (!tl_row_buffer.empty() && file_aligned.is_open()) {
                // 👑 修正錯位：強迫使用舊名字 (tl_active_row_name) 寫入上一行！
                std::string print_name = tl_active_row_name.empty() ? final_name : tl_active_row_name;
                file_aligned << "[" << print_name << "] " << tl_row_buffer << "\n";
                
                // 🎯 遵照指示：寫入 CSV 時輸出 Log
                LOGD("✅ [CSV寫入] 檔案: %s | 內容: %s", print_name.c_str(), tl_row_buffer.c_str());
                
                tl_row_buffer = "";
            }
            
            if (file_aligned.is_open()) {
                file_aligned << "\n\n==================================================\n"
                             << "=== [FILE_START: " << final_name << "] ===\n"
                             << "==================================================\n";
            }
            tl_last_reader_obj = p2;
        }

        if (col_idx == 0) {
            if (!tl_row_buffer.empty() && file_aligned.is_open()) {
                // 👑 修正錯位：一般換行時，也強迫使用舊名字 (tl_active_row_name)！
                std::string print_name = tl_active_row_name.empty() ? final_name : tl_active_row_name;
                file_aligned << "[" << print_name << "] " << tl_row_buffer << "\n";
                
                // 🎯 遵照指示：寫入 CSV 時輸出 Log
                LOGD("✅ [CSV寫入] 檔案: %s | 內容: %s", print_name.c_str(), tl_row_buffer.c_str());
            }
            tl_row_buffer = cell_data; 
            tl_active_row_name = final_name; // 👑 舊帳結清後，這行新資料才正式換上新名字！
        } else {
            tl_row_buffer += "," + cell_data; 
            tl_active_row_name = final_name; // 確保同一行內名字同步
        }
    }
    return result;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* reserved) {
    LOGD("🚀 Hook 模組已注入，啟動「指標 Bug 修復・零錯位最終版」系統...");

    file_aligned.open(PATH_ALIGNED, std::ios::out | std::ios::trunc);
    file_unique.open(PATH_UNIQUE, std::ios::out | std::ios::trunc);
    file_raw.open(PATH_RAW, std::ios::out | std::ios::trunc);

    if (file_aligned.is_open()) file_aligned << "=== PERFECT ALIGNED ASSETS STREAM ===\n";
    if (file_unique.is_open())  file_unique  << "=== UNIQUE FILENAMES MANIFEST ===\n";
    if (file_raw.is_open())     file_raw     << "=== RAW UNFILTERED CELL INTERCEPT STREAM ===\n";

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
        }

        void* addr_open = (void*)(base + RVA_OPEN_FILE);
        void* addr_parse = (void*)(base + RVA_CELL_PARSE);

        DobbyHook(addr_open, (void*)proxy_open_file, (void**)&orig_open_file);
        DobbyHook(addr_parse, (void*)proxy_cell_parse, (void**)&orig_cell_parse);

        LOGD("🛡️ [雙重保險天網就位] 錯位一格Bug已消滅，加上Log輸出，準備豐收！");
    }).detach();

    return JNI_VERSION_1_6;
}

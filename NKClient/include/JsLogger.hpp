#include <emscripten/emscripten.h>

class JsLogger {
public:
    template<typename... Args>
    static void Log(const char* fmt, Args... args) {
        logImpl(fmt, args...);
    }

private:
    template<typename... Args>
    static void logImpl(const char* fmt, Args... args) {
        EM_ASM({
            console.log(UTF8ToString($0), ...Array.prototype.slice.call(arguments, 1));
        }, fmt, args...);
    }
};

#include "frida-gum.h"
#include "LIEF/LIEF.hpp"
#include <chrono>

using std::chrono::duration_cast;

struct Profile;
struct _ProfilerCtx {
  GObject parent;
  GumInterceptor* interceptor = nullptr;
};

std::map<uintptr_t, std::chrono::system_clock::time_point> chrono;
std::map<uintptr_t, std::string> funcs;

using ProfilerCtx = _ProfilerCtx;

static void profiler_ctx_iface_init(gpointer g_iface, gpointer iface_data);

// Declare our new profiler type
G_DECLARE_FINAL_TYPE(ProfilerCtx, profiler_ctx, _, PROFILER, GObject)

// Make profiler extending GumObject
G_DEFINE_TYPE_EXTENDED(/* New type (CamelCase)  */ ProfilerCtx,
                       /* New type (snake_case) */ profiler_ctx,
                       /* Parent type           */ G_TYPE_OBJECT,
                       /* Some flags (unused)   */ 0,
                       G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                         profiler_ctx_iface_init
                       ))

// Equivalent of __cyg_profile_func_enter
void on_enter(GumInvocationListener* listener, GumInvocationContext* ic) {
  ProfilerCtx* self = __PROFILER(listener);
  const uintptr_t addr = GUM_IC_GET_FUNC_DATA(ic, uintptr_t);
  chrono[addr] = std::chrono::high_resolution_clock::now();
}

// Equivalent of __cyg_profile_func_exit
void on_leave (GumInvocationListener* listener, GumInvocationContext* ic) {
  ProfilerCtx* self = __PROFILER(listener);
  const auto addr = GUM_IC_GET_FUNC_DATA(ic, uintptr_t);
  const auto it_time = chrono.find(addr);
  if (it_time == std::end(chrono)) {
    return;
  }
  const auto start = it_time->second;
  const auto end = std::chrono::high_resolution_clock::now();
  const auto delta = end - start;
  const std::string& name = funcs[addr];
  printf("%s ran in %ld ms\n", name.c_str(),
      duration_cast<std::chrono::milliseconds>(delta).count());
}


void profiler_ctx_class_init(ProfilerCtxClass* klass) {
  (void) __IS_PROFILER;
  (void) glib_autoptr_cleanup_ProfilerCtx;
}

void profiler_ctx_iface_init(gpointer g_iface, gpointer iface_data) {
  auto* iface = static_cast<GumInvocationListenerInterface*>(g_iface);

  // Callback on hooked function enter / exit
  iface->on_enter = on_enter;
  iface->on_leave = on_leave;
}

void profiler_ctx_init(ProfilerCtx* ctx) {
  ctx->interceptor = gum_interceptor_obtain();
}

// ========================================================
#define PROFILE(X) profile_func(&X, #X)

struct Profiler {

  static void destroy() {
    gum_deinit_embedded();
  }
  static Profiler& get() {
    if (instance_ == nullptr) {
      gum_init_embedded();
      instance_ = std::make_unique<Profiler>();
      std::atexit(destroy);
    }
    return *instance_;

  }

  void setup() {
    PROFILE(LIEF::ELF::Parser::init);
    PROFILE(LIEF::ELF::Parser::parse_segments<LIEF::ELF::ELF64>);
  }

  Profiler() :
    ctx_{static_cast<ProfilerCtx*>(g_object_new(profiler_ctx_get_type(), nullptr))}
  {}

  template<typename Func>
  void profile_func(Func func, std::string name) {
    void* addr = cast_func(func);
    funcs[reinterpret_cast<uintptr_t>(addr)] = std::move(name);
    gum_interceptor_begin_transaction (ctx_->interceptor);
    gum_interceptor_attach (ctx_->interceptor,
        /* Target */ reinterpret_cast<gpointer>(addr),
        reinterpret_cast<GumInvocationListener*>(ctx_),
        /* id     */ reinterpret_cast<gpointer>(addr));
    gum_interceptor_end_transaction (ctx_->interceptor);
  }

  template<typename Func>
  static inline void* cast_func(Func f) {
    // Trick to cast a function pointer into a void*
    union {
      Func func;
      void* p;
    };
    func = f;
    return p;
  }

  ProfilerCtx* ctx_ = nullptr;
  static inline std::unique_ptr<Profiler> instance_;
};

int main(int argc, const char** argv) {
  if (argc != 2) {
    fprintf(stderr, "Usage: %s <elf binary>\n", argv[0]);
    return 1;
  }

  Profiler& prof = Profiler::get();
  prof.setup();
  LIEF::ELF::Parser::parse(argv[1]);
  return 0;
}

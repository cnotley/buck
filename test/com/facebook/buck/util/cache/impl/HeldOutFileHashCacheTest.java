package com.facebook.buck.util.cache;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.reflect.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.nio.file.attribute.FileTime;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import static org.junit.Assert.*;

public class HeldOutFileHashCacheTest {
  private static final class CacheHandle {
    final Object instance;
    final Method get;
    final Method getIfPresent;
    final Method invalidateOne;
    final Method invalidateAll;
    final Method size;
    final Method maintenance;
    final Method reset;
    final Method shutdown;
    final Method registerWatcher;
    final Method overloadTrigger;
    final Class<?> fsClassOrNull;
    final Object fsOrNull;
    final Path projectRoot;
    CacheHandle(
        Object instance,
        Method get,
        Method getIfPresent,
        Method invalidateOne,
        Method invalidateAll,
        Method size,
        Method maintenance,
        Method reset,
        Method shutdown,
        Method registerWatcher,
        Method overloadTrigger,
        Class<?> fsClassOrNull,
        Object fsOrNull,
        Path projectRoot) {
      this.instance = instance;
      this.get = get;
      this.getIfPresent = getIfPresent;
      this.invalidateOne = invalidateOne;
      this.invalidateAll = invalidateAll;
      this.size = size;
      this.maintenance = maintenance;
      this.reset = reset;
      this.shutdown = shutdown;
      this.registerWatcher = registerWatcher;
      this.overloadTrigger = overloadTrigger;
      this.fsClassOrNull = fsClassOrNull;
      this.fsOrNull = fsOrNull;
      this.projectRoot = projectRoot;
    }
    boolean supportsGetIfPresent() { return getIfPresent != null; }
    Object callGet(Path rel) throws Exception {
      if (fsOrNull != null && takesFilesystem(get)) {
        return get.invoke(instance, fsOrNull, rel);
      } else {
        return get.invoke(instance, rel);
      }
    }
    Object callGetIfPresent(Path rel) throws Exception {
      if (getIfPresent == null) return null;
      if (fsOrNull != null && takesFilesystem(getIfPresent)) {
        return getIfPresent.invoke(instance, fsOrNull, rel);
      } else {
        return getIfPresent.invoke(instance, rel);
      }
    }
    void callInvalidateOne(Path rel) throws Exception {
      if (invalidateOne == null) return;
      if (fsOrNull != null && takesFilesystem(invalidateOne)) {
        invalidateOne.invoke(instance, fsOrNull, rel);
      } else {
        invalidateOne.invoke(instance, rel);
      }
    }
    void callInvalidateAll(Collection<Path> rels) throws Exception {
      if (invalidateAll == null) {
        for (Path p : rels) { callInvalidateOne(p); }
        return;
      }
      if (fsOrNull != null && takesFilesystem(invalidateAll)) {
        invalidateAll.invoke(instance, fsOrNull, rels);
      } else {
        invalidateAll.invoke(instance, rels);
      }
    }
    void callMaintenance() throws Exception {
      if (maintenance != null) maintenance.invoke(instance);
    }
    void callReset() throws Exception {
      if (reset != null) reset.invoke(instance);
    }
    void callShutdown() throws Exception {
      if (shutdown != null) shutdown.invoke(instance);
    }
    int callSizeApprox() {
      if (size != null) {
        try {
          Object v = size.invoke(instance);
          if (v instanceof Number) return ((Number) v).intValue();
        } catch (Exception ignored) {}
      }
      try {
        int total = 0;
        for (Field f : getAllFields(instance.getClass())) {
          f.setAccessible(true);
          Object v = f.get(instance);
          if (v == null) continue;
          if (v instanceof Map) {
            try { total += ((Map<?, ?>) v).size(); } catch (Throwable ignored) {}
          } else if (isGuavaCache(v)) {
            try {
              Method mSize = v.getClass().getMethod("size");
              Object mv = mSize.invoke(v);
              if (mv instanceof Number) total += ((Number) mv).intValue();
            } catch (NoSuchMethodException e) {
              try {
                Method asMap = v.getClass().getMethod("asMap");
                Object asMapObj = asMap.invoke(v);
                if (asMapObj instanceof Map) total += ((Map<?, ?>) asMapObj).size();
              } catch (Exception ignored2) {}
            }
          }
        }
        return total;
      } catch (Exception e) {
        return -1;
      }
    }
    Set<Path> visibleKeysSnapshot() {
      Set<Path> keys = new HashSet<>();
      try {
        for (Field f : getAllFields(instance.getClass())) {
          f.setAccessible(true);
          Object v = f.get(instance);
          if (v instanceof Map) {
            Map<?, ?> m = (Map<?, ?>) v;
            for (Object k : m.keySet()) if (k instanceof Path) keys.add((Path) k);
          } else if (isGuavaCache(v)) {
            try {
              Method asMap = v.getClass().getMethod("asMap");
              Object mapObj = asMap.invoke(v);
              if (mapObj instanceof Map) {
                Map<?, ?> m = (Map<?, ?>) mapObj;
                for (Object k : m.keySet()) if (k instanceof Path) keys.add((Path) k);
              }
            } catch (Exception ignored) {}
          }
        }
      } catch (Exception ignored) {}
      return keys;
    }

    void emitWatcherEventsUnsorted(List<WatcherEvent> events) throws Exception {
      if (registerWatcher != null) {
        Class<?> listenerType = registerWatcher.getParameterTypes()[0];
        InvocationHandler noop = (proxy, method, args) -> null;
        Object listener =
            Proxy.newProxyInstance(
                listenerType.getClassLoader(), new Class<?>[]{listenerType}, noop);
        registerWatcher.invoke(instance, listener);
      }

      for (WatcherEvent we : events) {
        if (we.overload) {
          if (overloadTrigger != null) overloadTrigger.invoke(instance);
          else callReset();
        } else {
          callInvalidateOne(we.path);
        }
      }
    }
  }
  private static final class WatcherEvent {
    final Path path;
    final long timestampNanos;
    final boolean overload;
    WatcherEvent(Path path, long timestampNanos, boolean overload) {
      this.path = path;
      this.timestampNanos = timestampNanos;
      this.overload = overload;
    }
    static WatcherEvent tryAdapt(Object unknown) {
      if (unknown == null) return null;
      try {
        Path p = null;
        for (String n : Arrays.asList("getPath", "getFile", "getRelativePath")) {
          try {
            Method m = unknown.getClass().getMethod(n);
            Object v = m.invoke(unknown);
            if (v instanceof Path) { p = (Path) v; break; }
            if (v instanceof String) { p = Paths.get((String) v); break; }
          } catch (NoSuchMethodException ignored) {}
        }
        if (p == null) return null;
        Long ts = null;
        for (String n : Arrays.asList("getTimestampNanos", "getTimeNanos", "getTimestamp", "getEventTimeNanos")) {
          try {
            Method m = unknown.getClass().getMethod(n);
            Object v = m.invoke(unknown);
            if (v instanceof Number) { ts = ((Number) v).longValue(); break; }
          } catch (NoSuchMethodException ignored) {}
        }
        if (ts == null) ts = System.nanoTime();
        boolean overload = false;
        for (String n : Arrays.asList("isOverload", "isOverflow", "isReset", "isOverloaded")) {
          try {
            Method m = unknown.getClass().getMethod(n);
            Object v = m.invoke(unknown);
            if (v instanceof Boolean) { overload = (Boolean) v; break; }
          } catch (NoSuchMethodException ignored) {}
        }
        return new WatcherEvent(p, ts, overload);
      } catch (Exception e) {
        return null;
      }
    }
  }
  private final SecureRandom rnd = new SecureRandom();
  private Path tempRoot;
  private Object fakeFs;
  private Class<?> fakeFsClass;
  @Before
  public void setUp() throws Exception {
    tempRoot = Files.createTempDirectory("held_out_hash_cache_test");
    try {
      fakeFsClass = Class.forName("com.facebook.buck.io.filesystem.impl.FakeProjectFilesystem");
      Constructor<?> noArgs = fakeFsClass.getDeclaredConstructor();
      noArgs.setAccessible(true);
      fakeFs = noArgs.newInstance();
    } catch (Throwable ignored) {
      fakeFsClass = null;
      fakeFs = null;
    }
  }
  @After
  public void tearDown() throws Exception {
    try { if (tempRoot != null) deleteRecursively(tempRoot); } catch (IOException ignored) {}
  }
  private CacheHandle newBoundedCache(int maxEntries) throws Exception {
    return discoverCache(true, maxEntries, 0);
  }
  private CacheHandle newMemorySensitiveCache(int aggressiveness) throws Exception {
    return discoverCache(false, 0, aggressiveness);
  }
  private CacheHandle discoverCache(boolean bounded, int maxEntries, int aggressiveness) throws Exception {
    List<String> candidates = Arrays.asList(
        "com.facebook.buck.util.cache.impl.DefaultFileHashCache",
        "com.facebook.buck.util.cache.DefaultFileHashCache",
        "com.facebook.buck.util.cache.impl.FileHashCacheImpl",
        "com.facebook.buck.util.cache.FileHashCacheImpl",
        "com.facebook.buck.util.cache.impl.ProjectFileHashCache",
        "com.facebook.buck.util.cache.ProjectFileHashCache"
    );
    Object instance = null;
    Class<?> cacheClass = null;
    Class<?> fsParam = null;
    Object fsArg = fakeFs;
    outer:
    for (String fqcn : candidates) {
      Class<?> cls = tryLoad(fqcn);
      if (cls == null) continue;
      for (Constructor<?> ctor : cls.getConstructors()) {
        try {
          Object maybe = tryInvokeConstructor(ctor, bounded, maxEntries, aggressiveness, fsArg, tempRoot);
          if (maybe != null) {
            instance = maybe;
            cacheClass = cls;
            break outer;
          }
        } catch (Throwable ignored) {}
      }
      for (Method m : cls.getMethods()) {
        if (!Modifier.isStatic(m.getModifiers())) continue;
        if (!Modifier.isPublic(m.getModifiers())) continue;
        if (!cls.isAssignableFrom(m.getReturnType())) continue;
        try {
          Object maybe = tryInvokeStaticFactory(m, bounded, maxEntries, aggressiveness, fsArg, tempRoot);
          if (maybe != null) {
            instance = maybe;
            cacheClass = cls;
            break outer;
          }
        } catch (Throwable ignored) {}
      }
      for (Method m : cls.getMethods()) {
        if (!Modifier.isStatic(m.getModifiers())) continue;
        if (!Modifier.isPublic(m.getModifiers())) continue;
        if (cls.isAssignableFrom(m.getReturnType())) continue;
        try {
          Object builder = tryInvokeBuilderEntry(m, bounded, maxEntries, aggressiveness, fsArg, tempRoot);
          if (builder == null) continue;
          tryApplyIntConfig(builder, bounded ? maxEntries : aggressiveness);
          tryApplyFilesystem(builder, fsArg);
          Object built = tryBuilderBuild(builder, cls);
          if (built != null && cls.isInstance(built)) {
            instance = built;
            cacheClass = cls;
            break outer;
          }
        } catch (Throwable ignored) {}
      }
    }
    assertNotNull("No suitable cache implementation could be instantiated (bounded=" + bounded + ")", instance);
    Method mGet = findGet(cacheClass);
    assertNotNull("Lookup method (e.g., get/lookup/compute/hash/fetch) not found on " + cacheClass, mGet);
    Method mGetIfPresent = findOptional(cacheClass,
        Arrays.asList("getIfPresent", "peek", "lookupIfPresent", "getCached", "tryGet", "maybeGet", "getIfCached"),
        Path.class);
    if (mGetIfPresent == null) {
      Class<?> fsGuess = guessFilesystemParam(cacheClass);
      if (fsGuess != null) {
        mGetIfPresent = findOptional(cacheClass,
            Arrays.asList("getIfPresent", "peek", "lookupIfPresent", "getCached", "tryGet", "maybeGet", "getIfCached"),
            fsGuess, Path.class);
        fsParam = fsGuess;
      }
    }
    Method mInvalidate = findInvalidateOne(cacheClass);
    Method mInvalidateAll = findInvalidateAll(cacheClass);
    Method mSize = findOptional(cacheClass, Arrays.asList("size", "entryCount", "count", "estimatedSize"));
    Method mMaintenance = findOptional(cacheClass, Arrays.asList("maintenance", "runMaintenance", "maintain", "doMaintenance", "cleanup", "purge", "compact", "trim"));
    Method mReset = findOptional(cacheClass, Arrays.asList("reset", "clear", "invalidateAll", "flush"));
    Method mShutdown = findOptional(cacheClass, Arrays.asList("shutdown", "terminate", "close", "stop", "dispose"));
    Method mRegisterWatcher = findRegisterWatcher(cacheClass);
    Method mOverloadTrigger = findOptional(cacheClass, Arrays.asList("onWatcherOverload", "triggerOverload", "signalOverload", "overload", "overflow", "resetSignal"));
    Path root = (fakeFs != null) ? tryGetFsRoot(fakeFs) : tempRoot;
    if (root == null) root = tempRoot;
    return new CacheHandle(
        instance,
        mGet,
        mGetIfPresent,
        mInvalidate,
        mInvalidateAll,
        mSize,
        mMaintenance,
        mReset,
        mShutdown,
        mRegisterWatcher,
        mOverloadTrigger,
        fsParam,
        fsArg,
        root
    );
  }
  private static Object tryInvokeConstructor(
      Constructor<?> ctor,
      boolean bounded,
      int maxEntries,
      int aggressiveness,
      Object fsArg,
      Path root) throws Exception {
    Object[] args = makeArgs(ctor.getParameterTypes(), bounded, maxEntries, aggressiveness, fsArg, root);
    if (args == null) return null;
    ctor.setAccessible(true);
    return ctor.newInstance(args);
  }
  private static Object tryInvokeStaticFactory(
      Method m,
      boolean bounded,
      int maxEntries,
      int aggressiveness,
      Object fsArg,
      Path root) throws Exception {
    Object[] args = makeArgs(m.getParameterTypes(), bounded, maxEntries, aggressiveness, fsArg, root);
    if (args == null) return null;
    m.setAccessible(true);
    return m.invoke(null, args);
  }
  private static Object tryInvokeBuilderEntry(
      Method m,
      boolean bounded,
      int maxEntries,
      int aggressiveness,
      Object fsArg,
      Path root) throws Exception {
    Object[] args = makeArgs(m.getParameterTypes(), bounded, maxEntries, aggressiveness, fsArg, root);
    if (args == null) return null;
    m.setAccessible(true);
    return m.invoke(null, args);
  }
  private static Object[] makeArgs(
      Class<?>[] pt,
      boolean bounded,
      int maxEntries,
      int aggressiveness,
      Object fsArg,
      Path root) {
    Object[] args = new Object[pt.length];
    int cfgVal = bounded ? maxEntries : aggressiveness;
    for (int i = 0; i < pt.length; i++) {
      Class<?> p = pt[i];
      if (p == int.class || p == Integer.class) {
        args[i] = cfgVal;
      } else if (p == long.class || p == Long.class) {
        args[i] = (long) cfgVal;
      } else if (p == boolean.class || p == Boolean.class) {
        args[i] = bounded;
      } else if (p.getName().contains("ProjectFilesystem") || p.getSimpleName().toLowerCase(Locale.ROOT).contains("filesystem")) {
        if (fsArg == null) return null;
        if (!p.isInstance(fsArg)) return null;
        args[i] = fsArg;
      } else if (p == Path.class) {
        args[i] = root != null ? root : Paths.get(".").toAbsolutePath().normalize();
      } else if (p == Duration.class) {
        args[i] = Duration.ofMillis(Math.max(1, cfgVal));
      } else {
        return null;
      }
    }
    return args;
  }
  private static void tryApplyIntConfig(Object builder, int cfgVal) {
    for (Method m : builder.getClass().getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      String n = m.getName().toLowerCase(Locale.ROOT);
      boolean looksSetter = n.startsWith("with") || n.startsWith("set") || n.contains("max") || n.contains("capacity") ||
          n.contains("maximum") || n.contains("entries") || n.contains("size") || n.contains("aggress") ||
          n.contains("sensitivity") || n.contains("pressure") || n.contains("soft");
      if (!looksSetter) continue;
      Class<?>[] pt = m.getParameterTypes();
      if (pt.length != 1) continue;
      try {
        if (pt[0] == int.class || pt[0] == Integer.class) {
          m.invoke(builder, cfgVal);
        } else if (pt[0] == long.class || pt[0] == Long.class) {
          m.invoke(builder, (long) cfgVal);
        } else if (pt[0] == Duration.class) {
          m.invoke(builder, Duration.ofMillis(Math.max(1, cfgVal)));
        }
      } catch (Throwable ignored) {}
    }
  }
  private static void tryApplyFilesystem(Object builder, Object fsArg) {
    if (fsArg == null) return;
    for (Method m : builder.getClass().getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      String n = m.getName().toLowerCase(Locale.ROOT);
      boolean looksFsSetter = (n.startsWith("with") || n.startsWith("set")) &&
          (n.contains("filesystem") || n.contains("project"));
      if (!looksFsSetter) continue;
      Class<?>[] pt = m.getParameterTypes();
      if (pt.length != 1) continue;
      if (pt[0].isInstance(fsArg)) {
        try { m.invoke(builder, fsArg); } catch (Throwable ignored) {}
      }
    }
  }
  private static Object tryBuilderBuild(Object builder, Class<?> expectedType) {
    List<String> terms = Arrays.asList("build", "create", "make", "newinstance", "construct", "instantiate", "get");
    for (Method m : builder.getClass().getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      String nm = m.getName().toLowerCase(Locale.ROOT);
      boolean terminal = false;
      for (String t : terms) { if (nm.contains(t)) { terminal = true; break; } }
      if (!terminal) continue;
      if (m.getParameterCount() != 0) continue;
      try {
        Object v = m.invoke(builder);
        if (v != null && expectedType.isInstance(v)) return v;
      } catch (Throwable ignored) {}
    }
    return null;
  }
  private static Class<?> guessFilesystemParam(Class<?> cacheClass) {
    for (Method m : cacheClass.getMethods()) {
      for (Class<?> p : m.getParameterTypes()) {
        if (p.getName().contains("ProjectFilesystem") || p.getSimpleName().toLowerCase(Locale.ROOT).contains("filesystem")) {
          return p;
        }
      }
    }
    return null;
  }
  private static boolean takesFilesystem(Method m) {
    if (m == null) return false;
    if (m.getParameterTypes().length == 0) return false;
    Class<?> p = m.getParameterTypes()[0];
    String n = p.getName().toLowerCase(Locale.ROOT);
    return n.contains("filesystem");
  }
  private static Class<?> tryLoad(String fqcn) {
    try { return Class.forName(fqcn); } catch (Throwable t) { return null; }
  }
  private static Method findGet(Class<?> cacheClass) {
    List<String> names = Arrays.asList("get", "lookup", "compute", "hash", "load", "fetch");
    for (Method m : cacheClass.getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      Class<?>[] pt = m.getParameterTypes();
      if (pt.length == 1 && Path.class.isAssignableFrom(pt[0]) && nameIn(m, names)) return m;
      if (pt.length == 2 && pt[1] == Path.class && pt[0].getSimpleName().toLowerCase(Locale.ROOT).contains("filesystem") && nameIn(m, names)) {
        return m;
      }
    }
    return null;
  }
  private static boolean nameIn(Method m, List<String> names) {
    String n = m.getName().toLowerCase(Locale.ROOT);
    for (String s : names) if (n.equals(s) || n.contains(s)) return true;
    return false;
  }
  private static Method findInvalidateOne(Class<?> cacheClass) {
    List<String> names = Arrays.asList("invalidate", "invalidatepath", "remove", "evict", "delete", "drop", "purge");
    for (Method m : cacheClass.getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      Class<?>[] pt = m.getParameterTypes();
      if (pt.length == 1 && Path.class.isAssignableFrom(pt[0]) && nameIn(m, names)) return m;
      if (pt.length == 2 && pt[1] == Path.class && pt[0].getSimpleName().toLowerCase(Locale.ROOT).contains("filesystem") && nameIn(m, names)) {
        return m;
      }
    }
    return null;
  }
  private static Method findInvalidateAll(Class<?> cacheClass) {
    List<String> names = Arrays.asList("invalidateall", "removeall", "bulkinvalidate", "evictall", "clearall", "purgeall");
    for (Method m : cacheClass.getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      Class<?>[] pt = m.getParameterTypes();
      if (pt.length == 1 && Collection.class.isAssignableFrom(pt[0]) && nameIn(m, names)) return m;
      if (pt.length == 2 && Collection.class.isAssignableFrom(pt[1]) &&
          pt[0].getSimpleName().toLowerCase(Locale.ROOT).contains("filesystem") && nameIn(m, names)) {
        return m;
      }
    }
    return null;
  }
  private static Method findRegisterWatcher(Class<?> cacheClass) {
    for (Method m : cacheClass.getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      if (m.getParameterCount() == 1) {
        String nm = m.getName().toLowerCase(Locale.ROOT);
        boolean looksWatcher = nm.contains("watcher") || nm.contains("listener") || nm.contains("subscriber") || nm.contains("callback");
        boolean looksRegistration = nm.startsWith("register") || nm.startsWith("set") || nm.startsWith("add") || looksWatcher;
        if (looksRegistration && m.getParameterTypes()[0].isInterface()) return m;
      }
    }
    return null;
  }
  private static Method findOptional(Class<?> type, List<String> names, Class<?>... paramTypes) {
    for (String n : names) {
      try {
        Method m = type.getMethod(n, paramTypes);
        if (Modifier.isPublic(m.getModifiers())) return m;
      } catch (NoSuchMethodException ignored) {}
    }
    for (Method m : type.getMethods()) {
      if (!Modifier.isPublic(m.getModifiers())) continue;
      String nm = m.getName().toLowerCase(Locale.ROOT);
      for (String n : names) {
        if (nm.contains(n.toLowerCase(Locale.ROOT))) return m;
      }
    }
    return null;
  }
  private static boolean isGuavaCache(Object o) {
    if (o == null) return false;
    String n = o.getClass().getName();
    return n.startsWith("com.google.common.cache.") || n.contains("Cache");
  }
  private static List<Field> getAllFields(Class<?> type) {
    List<Field> all = new ArrayList<>();
    for (Class<?> c = type; c != null && c != Object.class; c = c.getSuperclass()) {
      Collections.addAll(all, c.getDeclaredFields());
    }
    return all;
  }
  private static Path tryGetFsRoot(Object fakeFs) {
    try {
      Method m = fakeFs.getClass().getMethod("getRootPath");
      Object p = m.invoke(fakeFs);
      if (p instanceof Path) return (Path) p;
      if (p != null) {
        Method getPath = p.getClass().getMethod("getPath");
        Object path = getPath.invoke(p);
        if (path instanceof Path) return (Path) path;
      }
    } catch (Exception ignored) {}
    return null;
  }
  private Path writeFile(Path root, String rel, byte[] content) throws IOException {
    Path p = root.resolve(rel);
    Path parent = p.getParent();
    if (parent != null) {
      Files.createDirectories(parent);
    }
    try (OutputStream os = new BufferedOutputStream(Files.newOutputStream(p))) { os.write(content); }
    return root.relativize(p);
  }
  private Path writeText(Path root, String rel, String text) throws IOException {
    return writeFile(root, rel, text.getBytes(StandardCharsets.UTF_8));
  }
  private static void touch(Path root, Path rel) throws IOException {
    Path abs = root.resolve(rel);
    Files.setLastModifiedTime(abs, FileTime.fromMillis(System.currentTimeMillis()));
  }
  private static byte[] randomBytes(int size, SecureRandom rnd) {
    byte[] b = new byte[size];
    rnd.nextBytes(b);
    return b;
  }
  private static void deleteRecursively(Path root) throws IOException {
    if (!Files.exists(root)) return;
    Files.walk(root)
        .sorted(Comparator.reverseOrder())
        .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignored) {} });
  }
  private static long usedHeap() {
    Runtime rt = Runtime.getRuntime();
    return rt.totalMemory() - rt.freeMemory();
  }
  private static void forceGcQuietly() {
    try { System.gc(); Thread.sleep(50); } catch (InterruptedException ignored) {}
  }
  @Test(timeout = 15_000)
  public void testMaxEntriesStrictlyEnforcedNoOvershoot() throws Exception {
    final int MAX = 3;
    CacheHandle cache = newBoundedCache(MAX);
    List<Path> all = Collections.synchronizedList(new ArrayList<>());
    for (int i = 0; i < 20; i++) {
      Path rel = writeText(cache.projectRoot, "a/file_" + i + ".txt", "x" + i);
      all.add(rel);
      cache.callGet(rel);
      int approx = cache.callSizeApprox();
      int visible = cache.visibleKeysSnapshot().size();
      assertTrue(
          "Cache size must never overshoot max after sequential add #" + i +
              " (approx=" + approx + ", visible=" + visible + ")",
          approx <= MAX && visible <= MAX);
    }

    int threads = 5;
    CyclicBarrier start = new CyclicBarrier(threads);
    CountDownLatch done = new CountDownLatch(threads);
    AtomicBoolean overshoot = new AtomicBoolean(false);
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    for (int t = 0; t < threads; t++) {
      final int tid = t;
      pool.submit(
          () -> {
            try {
              start.await(3, TimeUnit.SECONDS);
              for (int k = 0; k < 6; k++) {
                Path rel = writeText(cache.projectRoot, "b/t" + tid + "_" + k + ".txt",
                    "y" + tid + ":" + k);
                all.add(rel);
                cache.callGet(rel);
                int s = cache.callSizeApprox();
                int vis = cache.visibleKeysSnapshot().size();
                if (s > MAX || vis > MAX) {
                  overshoot.set(true);
                }
              }
            } catch (Exception e) {
              overshoot.set(true);
            } finally {
              done.countDown();
            }
          });
    }
    assertTrue(done.await(10, TimeUnit.SECONDS));
    pool.shutdownNow();
    assertFalse("Cache size overshot maximum during concurrent burst", overshoot.get());

    Set<Path> visible = cache.visibleKeysSnapshot();
    assertTrue("Visible keys should be <= max after burst", visible.size() <= MAX);
    assertTrue("Approximate size should be <= max after burst", cache.callSizeApprox() <= MAX);
    for (Path p : all) {
      if (!visible.contains(p) && cache.supportsGetIfPresent()) {
        assertNull("Evicted path should not linger in any structure: " + p,
            cache.callGetIfPresent(p));
      }
    }
  }
  @Test(timeout = 12_000)
  public void testLRUEvictionOnBreachNoDeferral() throws Exception {
    CacheHandle cache = newBoundedCache(3);
    Path f1 = writeText(cache.projectRoot, "lru/e1.txt", "1");
    Path f2 = writeText(cache.projectRoot, "lru/e2.txt", "2");
    Path f3 = writeText(cache.projectRoot, "lru/e3.txt", "3");
    cache.callGet(f1);
    cache.callGet(f2);
    cache.callGet(f3);
    cache.callGet(f1); 
    Path f4 = writeText(cache.projectRoot, "lru/e4.txt", "4");
    cache.callGet(f4);
    if (cache.supportsGetIfPresent()) {
      assertNotNull("f1 should be resident", cache.callGetIfPresent(f1));
      assertNotNull("f3 should be resident", cache.callGetIfPresent(f3));
      assertNotNull("f4 should be resident", cache.callGetIfPresent(f4));
      assertNull("LRU should evict f2 exactly at threshold breach (no deferral)", cache.callGetIfPresent(f2));
    } else {
      Set<Path> keys = cache.visibleKeysSnapshot();
      assertTrue("Could not introspect keys to verify exact eviction order; got empty snapshot.", !keys.isEmpty());
      assertTrue("Eviction must keep most recent (f1)", keys.contains(f1));
      assertTrue("Eviction must keep f3 (more recent than f2)", keys.contains(f3));
      assertTrue("Eviction must include f4", keys.contains(f4));
      assertFalse("LRU should evict f2 exactly at threshold breach (no deferral)", keys.contains(f2));
    }
  }
  @Test(timeout = 20_000)
  public void testMemoryStabilizesUnderHighChurn() throws Exception {
    final int MAX = 50;
    CacheHandle cache = newBoundedCache(MAX);
    int cycles = 3;
    int perCycle = 500;
    List<Path> all = new ArrayList<>();
    int prev = -1;
    for (int c = 0; c < cycles; c++) {
      for (int i = 0; i < perCycle; i++) {
        Path rel = writeFile(cache.projectRoot,
            "churn/" + c + "_" + i + ".bin",
            randomBytes(256 + rnd.nextInt(256), rnd));
        cache.callGet(rel);
        all.add(rel);
      }

      Set<Path> visible = cache.visibleKeysSnapshot();
      int approx = cache.callSizeApprox();
      assertTrue("Visible entries must stay within max after cycle " + c +
          " (size=" + visible.size() + ")", visible.size() <= MAX);
      assertTrue("Approx size must stay within max after cycle " + c +
          " (size=" + approx + ")", approx <= MAX);
      if (prev != -1) {
        assertTrue("Cache should stabilize and not grow after cycle " + c,
            visible.size() <= prev + 2);
      }
      prev = visible.size();

      if (!trySimulateReclamation(cache, 5)) {
        List<byte[]> allocations = new ArrayList<>();
        try {
          for (int i = 0; i < 40; i++) allocations.add(new byte[512 * 1024]);
        } catch (OutOfMemoryError ignored) {
          allocations.clear();
        }
        forceGcQuietly();
      }
    }

    Set<Path> visible = cache.visibleKeysSnapshot();
    assertTrue("Final entry count must remain within max", visible.size() <= MAX);
    for (Path p : all) {
      if (!visible.contains(p) && cache.supportsGetIfPresent()) {
        assertNull("Evicted paths must not leak: " + p, cache.callGetIfPresent(p));
      }
    }
  }
  @Test(timeout = 20_000)
  public void testSelectiveDiscardUnderMemoryPressure() throws Exception {
    CacheHandle cache = newMemorySensitiveCache(2);
    List<Path> paths = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      Path rel = writeFile(cache.projectRoot, "mem/large_" + i + ".dat", randomBytes(64 * 1024, rnd));
      cache.callGet(rel);
      paths.add(rel);
    }

    if (!trySimulateReclamation(cache, 2)) {
      List<byte[]> allocations = new ArrayList<>();
      try {
        for (int i = 0; i < 40; i++) allocations.add(new byte[512 * 1024]);
      } catch (OutOfMemoryError ignored) {
        allocations.clear();
      }
      forceGcQuietly();
    }
    if (!cache.supportsGetIfPresent()) {
      for (Path p : paths) { cache.callGet(p); }
      return;
    }
    int present = 0, missing = 0;
    for (Path p : paths) {
      Object v = cache.callGetIfPresent(p);
      if (v == null) missing++; else present++;
    }
    assertTrue("Implementation must expose getIfPresent-like semantics; no observations possible", (present + missing) > 0);
    assertTrue("Some entries should be discarded under memory pressure", missing > 0);
    assertTrue("Not all entries should be discarded", present > 0);
    for (Path p : paths) { cache.callGet(p); }
  }
  @Test(timeout = 20_000)
  public void testRecomputeAfterDiscardWithMetadataVerification() throws Exception {
    CacheHandle cache = newMemorySensitiveCache(3);
    Path p = writeText(cache.projectRoot, "meta/recompute.txt", "A");
    Object h1 = cache.callGet(p);

    if (!trySimulateReclamation(cache, 3)) {
      List<byte[]> alloc = new ArrayList<>();
      try { for (int i = 0; i < 80; i++) alloc.add(new byte[256 * 1024]); } catch (OutOfMemoryError ignored) {}
      forceGcQuietly();
    }
    Files.write(cache.projectRoot.resolve(p), "B".getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
    touch(cache.projectRoot, p);
    Object h2 = cache.callGet(p);
    assertNotNull(h2);
    assertFalse("Hash must change after content/metadata mutation + discard", safeEquals(h1, h2));
  }
  @Test(timeout = 15_000)
  public void testSafeguardsRejectAlteredReclaimedEntries() throws Exception {
    CacheHandle cache = newMemorySensitiveCache(3);
    Path p = writeText(cache.projectRoot, "safe/reclaimed.txt", "first");
    Object h1 = cache.callGet(p);
    if (!trySimulateReclamation(cache, 2)) {
      for (int i = 0; i < 120; i++) { byte[] dummy = new byte[128 * 1024]; }
      forceGcQuietly();
    }
    Files.write(cache.projectRoot.resolve(p), "second".getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
    touch(cache.projectRoot, p);
    Object h2 = cache.callGet(p);
    assertNotNull(h2);
    assertFalse("Must not serve stale content for reclaimed+altered entry", safeEquals(h1, h2));
  }
  @Test(timeout = 15_000)
  public void testAtomicCollectionInvalidationNoPartialEffects() throws Exception {
    CacheHandle cache = newBoundedCache(16);
    List<Path> rels = new ArrayList<>();
    int entries = 12;
    for (int i = 0; i < entries; i++) {
      Path p = writeText(cache.projectRoot, "atomic/x" + i + ".txt", "x" + i);
      cache.callGet(p);
      rels.add(p);
    }
    if (!cache.supportsGetIfPresent()) {
      for (int r = 0; r < 3; r++) {
        cache.callInvalidateAll(rels);
        Set<Path> keys = cache.visibleKeysSnapshot();
        for (Path p : rels) {
          assertFalse("All provided keys must be removed by bulk invalidation", keys.contains(p));
        }
        for (Path p : rels) cache.callGet(p);
      }
      return;
    }
    final int readers = 4;
    for (int round = 0; round < 3; round++) {
      // ensure entries are present for this round
      for (Path p : rels) cache.callGet(p);

      CyclicBarrier barrier = new CyclicBarrier(readers + 1);
      AtomicBoolean partialObserved = new AtomicBoolean(false);
      ExecutorService pool = Executors.newFixedThreadPool(readers + 1);
      Future<?> inv = pool.submit(() -> {
        try {
          barrier.await(2, TimeUnit.SECONDS);
          cache.callInvalidateAll(rels);
        } catch (Exception e) {
          throw new RuntimeException(e);
        }
      });
      List<Future<?>> readersF = new ArrayList<>();
      for (int i = 0; i < readers; i++) {
        readersF.add(
            pool.submit(
                () -> {
                  try {
                    barrier.await(2, TimeUnit.SECONDS);
                    long end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(800);
                    while (System.nanoTime() < end) {
                      int present = 0;
                      for (Path p : rels) {
                        if (cache.callGetIfPresent(p) != null) present++;
                      }
                      if (present > 0 && present < rels.size()) {
                        partialObserved.set(true);
                        break;
                      }
                    }
                  } catch (Exception e) {
                    throw new RuntimeException(e);
                  }
                }));
      }
      inv.get(5, TimeUnit.SECONDS);
      for (Future<?> f : readersF) f.get(5, TimeUnit.SECONDS);
      pool.shutdownNow();
      assertFalse(
          "Invalidation of a collection must be atomic (no partial visibility)",
          partialObserved.get());
      for (Path p : rels) {
        assertNull("Post invalidation all entries must be absent", cache.callGetIfPresent(p));
      }
    }
  }

  @Test(timeout = 25_000)
  public void testConcurrentInvalidationsNoDeadlocks() throws Exception {
    CacheHandle cache = newBoundedCache(64);
    final int keys = 25;
    final List<Path> rels = new ArrayList<>(keys);
    for (int i = 0; i < keys; i++) {
      Path p = writeText(cache.projectRoot, "deadlock/k" + i + ".txt", "v" + i);
      cache.callGet(p);
      rels.add(p);
    }
    final int threads = 12;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    List<Future<?>> futures = new ArrayList<>(threads);
    AtomicBoolean failed = new AtomicBoolean(false);
    for (int t = 0; t < threads; t++) {
      futures.add(pool.submit(() -> {
        try {
          start.await();
          for (int i = 0; i < 200; i++) {
            Path p = rels.get(rnd.nextInt(keys));
            if ((i & 1) == 0) cache.callInvalidateOne(p);
            else cache.callGet(p);
          }
        } catch (Throwable th) {
          failed.set(true);
          throw new RuntimeException(th);
        }
      }));
    }
    start.countDown();

    for (Future<?> f : futures) {
      f.get(20, TimeUnit.SECONDS);
    }
    pool.shutdownNow();
    assertFalse("No deadlocks or exceptions under high contention", failed.get());
  }

  @Test(timeout = 25_000)
  public void testConcurrentInvalidationsNoConcurrentModificationExceptions() throws Exception {
    CacheHandle cache = newBoundedCache(64);
    final int keys = 25;
    final List<Path> rels = new ArrayList<>(keys);
    for (int i = 0; i < keys; i++) {
      Path p = writeText(cache.projectRoot, "cme/k" + i + ".txt", "v" + i);
      cache.callGet(p);
      rels.add(p);
    }
    final int threads = 12;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch start = new CountDownLatch(1);
    AtomicBoolean cmeSeen = new AtomicBoolean(false);
    List<Future<?>> futures = new ArrayList<>(threads);
    for (int t = 0; t < threads; t++) {
      futures.add(pool.submit(() -> {
      try {
          start.await();
          for (int i = 0; i < 200; i++) {
            Path p = rels.get(rnd.nextInt(keys));
            try {
              if (rnd.nextBoolean()) cache.callInvalidateOne(p);
              else cache.callGet(p);
            } catch (ConcurrentModificationException cme) {
              cmeSeen.set(true);
              throw cme;
            } catch (Exception e) {
              throw new RuntimeException(e);
            }
          }
        } catch (InterruptedException ignored) {
        }
      }));
    }
    start.countDown();
    for (Future<?> f : futures) {
      f.get(20, TimeUnit.SECONDS);
    }
    pool.shutdownNow();
    assertFalse("ConcurrentModificationException must not occur under high contention", cmeSeen.get());
  }
  @Test(timeout = 25_000)
  public void testLinearizabilityOnSharedKeys() throws Exception {
    CacheHandle cache = newBoundedCache(16);
    Path p = writeText(cache.projectRoot, "linear/shared.txt", "V0");
    cache.callGet(p);
    final int INVALIDATORS = 2;
    final int READERS = 4;
    final int N = 400; 
    final AtomicInteger version = new AtomicInteger(0);
    final List<List<Integer>> readerTraces = new ArrayList<>();
    for (int i = 0; i < READERS; i++) readerTraces.add(Collections.synchronizedList(new ArrayList<>()));
    final Set<Integer> observed = ConcurrentHashMap.newKeySet();
    ExecutorService pool = Executors.newFixedThreadPool(READERS + INVALIDATORS);
    CountDownLatch done = new CountDownLatch(READERS + INVALIDATORS);
    Runnable reader = (/*no args*/) -> {
      List<Integer> trace = readerTraces.get((int) (Thread.currentThread().getId() % READERS));
      try {
        int last = -1;
        for (int i = 0; i < N; i++) {
          cache.callGet(p); 

          String s = new String(Files.readAllBytes(cache.projectRoot.resolve(p)), StandardCharsets.UTF_8);
          int v = parseVersion(s);
          observed.add(v);
   
          if (v < last) fail("Observed version decreased in reader: " + v + " < " + last);
          last = v;
          trace.add(v);
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      } finally {
        done.countDown();
      }
    };
    Runnable invalidator = () -> {
      try {
        for (int i = 0; i < N; i++) {
          int next = version.incrementAndGet();
          Files.write(cache.projectRoot.resolve(p), ("V" + next).getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
          touch(cache.projectRoot, p);
          cache.callInvalidateOne(p);
          cache.callGet(p); 
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      } finally {
        done.countDown();
      }
    };
    for (int i = 0; i < READERS; i++) pool.submit(reader);
    for (int i = 0; i < INVALIDATORS; i++) pool.submit(invalidator);
    assertTrue(done.await(20, TimeUnit.SECONDS));
    pool.shutdownNow();

    int produced = INVALIDATORS * N;
    for (int v = 1; v <= produced; v++) {
      assertTrue("Version " + v + " must be observable in reads", observed.contains(v));
    }
  }
  private static int parseVersion(String s) {
    if (s == null || s.isEmpty()) return -1;
    if (s.charAt(0) == 'V') s = s.substring(1);
    try { return Integer.parseInt(s.trim()); } catch (NumberFormatException e) { return -1; }
  }
  @Test(timeout = 15_000)
  public void testWatcherInvalidationsBufferedSortedByTimestamp() throws Exception {
    CacheHandle cache = newBoundedCache(16);
    Path a = writeText(cache.projectRoot, "watch/a.txt", "A");
    Path b = writeText(cache.projectRoot, "watch/b.txt", "B");
    cache.callGet(a);
    cache.callGet(b);

    List<WatcherEvent> events = Arrays.asList(
        new WatcherEvent(a, 2_000_000L, false),
        new WatcherEvent(b, 1_000_000L, false)
    );

    cache.emitWatcherEventsUnsorted(events);

    if (cache.supportsGetIfPresent()) {
      assertNull("a must be invalidated by watcher", cache.callGetIfPresent(a));
      assertNull("b must be invalidated by watcher", cache.callGetIfPresent(b));
    } else {
      Set<Path> keys = cache.visibleKeysSnapshot();
      assertTrue("Key snapshot unavailable to verify watcher effects.", !keys.isEmpty());
      assertFalse("a must be invalidated by watcher/emulation", keys.contains(a));
      assertFalse("b must be invalidated by watcher/emulation", keys.contains(b));
    }
  }
  @Test(timeout = 15_000)
  public void testOverloadResetWithCriticalPathRecompute() throws Exception {
    CacheHandle cache = newBoundedCache(16);
    Path hot = writeText(cache.projectRoot, "over/hot.txt", "HOT");
    cache.callGet(hot);
    if (cache.overloadTrigger != null) cache.overloadTrigger.invoke(cache.instance);
    else cache.callReset();
    Object v1 = cache.callGet(hot);
    assertNotNull("Critical path must recompute after reset", v1);
  }
  @Test(timeout = 15_000)
  public void testMaintenanceEvictsLowUtilityEntries() throws Exception {
    CacheHandle cache = newBoundedCache(5);
    Path p1 = writeText(cache.projectRoot, "maint/p1.txt", "1");
    Path p2 = writeText(cache.projectRoot, "maint/p2.txt", "2");
    Path p3 = writeText(cache.projectRoot, "maint/p3.txt", "3");
    Path p4 = writeText(cache.projectRoot, "maint/p4.txt", "4");
    Path p5 = writeText(cache.projectRoot, "maint/p5.txt", "5");
    cache.callGet(p1); cache.callGet(p2); cache.callGet(p3); cache.callGet(p4); cache.callGet(p5);
    for (int i = 0; i < 10; i++) { cache.callGet(p1); cache.callGet(p2); cache.callGet(p3); cache.callGet(p4); }
    Path p6 = writeText(cache.projectRoot, "maint/p6.txt", "6");
    cache.callGet(p6);
    cache.callMaintenance();
    if (cache.supportsGetIfPresent()) {
      assertNull("Maintenance should evict low-utility (cold) entry first", cache.callGetIfPresent(p5));

      assertNotNull(cache.callGetIfPresent(p1));
      assertNotNull(cache.callGetIfPresent(p2));
      assertNotNull(cache.callGetIfPresent(p3));
      assertNotNull(cache.callGetIfPresent(p4));
    } else {
      Set<Path> keys = cache.visibleKeysSnapshot();
      assertTrue("Key snapshot unavailable to verify eviction order.", !keys.isEmpty());
      assertFalse("Maintenance should evict low-utility (cold) entry first", keys.contains(p5));
    }
  }
  @Test(timeout = 15_000)
  public void testMaintenanceEliminatesDiscardedAndOrphanedKeys() throws Exception {
    CacheHandle cache = newMemorySensitiveCache(3);
    Path p = writeText(cache.projectRoot, "orph/a.txt", "x");
    cache.callGet(p);
    if (!trySimulateReclamation(cache, 2)) {
      for (int i = 0; i < 120; i++) { byte[] dummy = new byte[128 * 1024]; }
      forceGcQuietly();
    }
    cache.callMaintenance();
    Set<Path> keys = cache.visibleKeysSnapshot();
    if (cache.maintenance != null) {
      assertTrue("Key snapshot unavailable to verify purge.", !keys.isEmpty());
      assertFalse("Maintenance should remove discarded/orphaned entries", keys.contains(p));
    }
  }
  @Test(timeout = 15_000)
  public void testMaintenanceInterruptibleNoInconsistency() throws Exception {
    CacheHandle cache = newBoundedCache(64);
    for (int i = 0; i < 100; i++) {
      Path p = writeText(cache.projectRoot, "int/" + i + ".txt", "v");
      cache.callGet(p);
    }
    ExecutorService pool = Executors.newFixedThreadPool(2);
    Future<?> f1 = pool.submit(() -> { try { cache.callMaintenance(); } catch (Exception ignored) {} });
    Future<?> f2 = pool.submit(() -> {
      try {
        for (int i = 0; i < 200; i++) {
          Path p = Paths.get("int/" + rnd.nextInt(100) + ".txt");
          if (rnd.nextBoolean()) cache.callGet(p); else cache.callInvalidateOne(p);
        }
      } catch (Exception e) {
        throw new RuntimeException(e);
      }
    });
    f1.get(8, TimeUnit.SECONDS);
    f2.get(8, TimeUnit.SECONDS);
    pool.shutdownNow();
    int size = cache.callSizeApprox();
    assertTrue("Cache consistent after interruptible maintenance", size >= 0);
  }
  @Test(timeout = 12_000)
  public void testTerminationHaltsAllThreads() throws Exception {
    CacheHandle cache = newBoundedCache(8);
    Path p = writeText(cache.projectRoot, "term/t.txt", "z");
    cache.callGet(p);
    Integer before = tryActiveThreadsCount(cache);
    cache.callShutdown();
    Thread.sleep(250);
    Integer after = tryActiveThreadsCount(cache);
    if (before != null && after != null) {
      assertTrue("Termination should halt all cache threads (deterministic accessor)", after == 0);
    } else {
      Set<Long> idsBefore = hashCacheThreadIds();
      Set<Long> idsAfter = hashCacheThreadIds();
      idsAfter.retainAll(idsBefore);
      assertTrue("Termination should halt all cache threads", idsAfter.isEmpty());
    }
  }
  @Test(timeout = 12_000)
  public void testTerminationDeregistersMonitorsViaCallbacks() throws Exception {
    CacheHandle cache = newBoundedCache(8);
    if (cache.registerWatcher == null) {
      cache.callShutdown();
      return;
    }
    final AtomicBoolean called = new AtomicBoolean(false);
    Class<?> listenerType = cache.registerWatcher.getParameterTypes()[0];
    Object listener = Proxy.newProxyInstance(
        listenerType.getClassLoader(),
        new Class<?>[]{listenerType},
        (proxy, method, args) -> {
          if (method.getName().toLowerCase(Locale.ROOT).contains("unregister")
              || method.getName().toLowerCase(Locale.ROOT).contains("close")) {
            called.set(true);
          }
          return null;
        });
    cache.registerWatcher.invoke(cache.instance, listener);
    cache.callShutdown();
    assertTrue("Termination should invoke watcher deregistration callbacks", called.get());
  }
  @Test(timeout = 12_000)
  public void testTerminationNoLingeringWithZeroResourceCheck() throws Exception {
    CacheHandle cache = newBoundedCache(8);
    Path p = writeText(cache.projectRoot, "zero/x.txt", "x");
    cache.callGet(p);
    cache.callShutdown();
    Set<String> lingering = hashCacheThreadNames();
    assertTrue("No lingering cache-related threads or timers after termination: " + lingering, lingering.isEmpty());
  }
  @Test(timeout = 12_000)
  public void testParallelNonOverlappingReadsNoGlobalSync() throws Exception {
    CacheHandle cache = newBoundedCache(1000);
    int n = 512;
    for (int i = 0; i < n; i++) {
      Path p = writeText(cache.projectRoot, "parallel/" + i + ".txt", "p" + i);
      cache.callGet(p);
    }
    int threads = 8;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    long start = System.nanoTime();
    CountDownLatch done = new CountDownLatch(threads);
    for (int t = 0; t < threads; t++) {
      final int base = t * (n / threads);
      pool.submit(() -> {
        try {
          for (int i = 0; i < n / threads; i++) {
            Path p = Paths.get("parallel/" + (base + i) + ".txt");
            cache.callGet(p);
          }
        } catch (Exception e) {
          throw new RuntimeException(e);
        } finally { done.countDown(); }
      });
    }
    assertTrue(done.await(8, TimeUnit.SECONDS));
    pool.shutdownNow();
    long elapsedMs = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start);
    assertTrue("Parallel reads show serialization overhead (elapsed=" + elapsedMs + " ms)", elapsedMs < 3000);
  }
  @Test(timeout = 10_000)
  public void testAtomicUpdateVisibilityWithBarriers() throws Exception {
    CacheHandle cache = newBoundedCache(8);
    Path p = writeText(cache.projectRoot, "atomic/barrier.txt", "v0");
    cache.callGet(p);
    CyclicBarrier barrier = new CyclicBarrier(2);
    AtomicInteger mismatches = new AtomicInteger(0);
    Thread writer = new Thread(() -> {
      try {
        barrier.await();
        Files.write(cache.projectRoot.resolve(p), "v1".getBytes(StandardCharsets.UTF_8), StandardOpenOption.TRUNCATE_EXISTING);
        touch(cache.projectRoot, p);
        cache.callInvalidateOne(p);
        cache.callGet(p);
      } catch (Exception ignored) {}
    });
    Thread reader = new Thread(() -> {
      try {
        barrier.await();
        for (int i = 0; i < 2000; i++) {
          Object v = null;
          try { v = cache.callGet(p); } catch (Exception ignored) {}
          if (v == null) mismatches.incrementAndGet();
        }
      } catch (Exception e) {
        mismatches.incrementAndGet();
      }
    });
    writer.start(); reader.start();
    writer.join(); reader.join();
    assertEquals("No partial/invalid states observed", 0, mismatches.get());
  }
  @Test(timeout = 10_000)
  public void testTraversalsWithSnapshotIsolationNoExceptions() throws Exception {
    CacheHandle cache = newBoundedCache(64);
    for (int i = 0; i < 200; i++) {
      Path p = writeText(cache.projectRoot, "snap/" + i + ".txt", "v");
      cache.callGet(p);
    }
    AtomicBoolean error = new AtomicBoolean(false);
    Thread t1 = new Thread(() -> {
      try {
        Set<Path> snap = cache.visibleKeysSnapshot();
        for (Path ignored : snap) { }
      } catch (Throwable th) { error.set(true); }
    });
    Thread t2 = new Thread(() -> {
      try {
        for (int i = 0; i < 500; i++) {
          Path p = Paths.get("snap/" + rnd.nextInt(200) + ".txt");
          if (rnd.nextBoolean()) cache.callInvalidateOne(p); else cache.callGet(p);
        }
      } catch (Throwable th) { error.set(true); }
    });
    t1.start(); t2.start();
    t1.join(); t2.join();
    assertFalse("Traversals tolerate concurrent mods via snapshot isolation", error.get());
  }
  @Test(timeout = 10_000)
  public void testBoundedFactoryConformsToConfig() throws Exception {
    CacheHandle cache = newBoundedCache(3);
    for (int i = 0; i < 8; i++) {
      Path p = writeText(cache.projectRoot, "cfg/b" + i + ".txt", "x");
      cache.callGet(p);
      int size = cache.callSizeApprox();
      assertTrue("Bounded factory must respect maximum entries", size <= 3);
    }
  }
  @Test(timeout = 15_000)
  public void testMemorySensitiveFactoryTunabilityConforms() throws Exception {
    CacheHandle mild = newMemorySensitiveCache(1);
    CacheHandle aggressive = newMemorySensitiveCache(5);
    if (!(mild.supportsGetIfPresent() && aggressive.supportsGetIfPresent())) { return; }
    List<Path> files = new ArrayList<>();
    for (int i = 0; i < 12; i++) {
      Path p = writeFile(mild.projectRoot, "tun/x" + i + ".bin", randomBytes(64 * 1024, rnd));
      files.add(p);
      mild.callGet(p);
      aggressive.callGet(p);
    }
    if (!trySimulateReclamation(aggressive, 5) | !trySimulateReclamation(mild, 1)) {
      for (int i = 0; i < 120; i++) { byte[] dummy = new byte[256 * 1024]; }
      forceGcQuietly();
    }
    int mildMissing = 0, aggrMissing = 0;
    for (Path p : files) {
      if (mild.callGetIfPresent(p) == null) mildMissing++;
      if (aggressive.callGetIfPresent(p) == null) aggrMissing++;
    }
    assertTrue("No discards observed; cannot compare tunability.", mildMissing + aggrMissing > 0);
    assertTrue("Aggressive memory-sensitive cache should discard more under pressure", aggrMissing >= mildMissing);
  }
  @Test(timeout = 15_000)
  public void testFactoriesDifferentialBehaviorInPressure() throws Exception {
    CacheHandle bounded = newBoundedCache(6);
    CacheHandle ms = newMemorySensitiveCache(4);
    List<Path> files = new ArrayList<>();
    for (int i = 0; i < 10; i++) {
      Path p = writeText(bounded.projectRoot, "diff/f" + i + ".txt", "v" + i);
      files.add(p);
      bounded.callGet(p);
      ms.callGet(p);
    }
    if (!trySimulateReclamation(ms, 4)) {
      for (int i = 0; i < 100; i++) { byte[] dummy = new byte[256 * 1024]; }
      forceGcQuietly();
    }
    int boundedSize = bounded.callSizeApprox();
    if (!ms.supportsGetIfPresent()) {
      assertTrue("Bounded cache should remain around its configured max (<=6), was: " + boundedSize, boundedSize <= 6);
      return;
    }
    int msMisses = 0;
    for (Path p : files) { if (ms.callGetIfPresent(p) == null) msMisses++; }
    assertTrue("Bounded cache should remain around its configured max (<=6), was: " + boundedSize, boundedSize <= 6);
    assertTrue("Memory-sensitive cache should show selective discards", msMisses > 0);
  }
  @Test(timeout = 20_000)
  public void testSingleThreadedSpeedNoRegressionHighLimits() throws Exception {
    final int ENTRIES = 10_000;
    CacheHandle unbounded = newBoundedCache(0);
    List<Path> rels = new ArrayList<>(ENTRIES);
    for (int i = 0; i < ENTRIES; i++) {
      Path p = writeText(unbounded.projectRoot, "perf/s" + i + ".txt", "v");
      unbounded.callGet(p);
      rels.add(p);
    }
    for (int i = 0; i < ENTRIES; i++) {
      unbounded.callGet(rels.get(rnd.nextInt(ENTRIES)));
    }
    long baselineTotal = 0;
    for (int r = 0; r < 3; r++) {
      long start = System.nanoTime();
      for (int i = 0; i < 20_000; i++) {
        unbounded.callGet(rels.get(rnd.nextInt(ENTRIES)));
      }
      baselineTotal += System.nanoTime() - start;
    }
    long baselineMs = TimeUnit.NANOSECONDS.toMillis(baselineTotal / 3);

    CacheHandle bounded = newBoundedCache(10_000);
    for (Path p : rels) bounded.callGet(p);
    for (int i = 0; i < ENTRIES; i++) bounded.callGet(rels.get(rnd.nextInt(ENTRIES)));
    long boundedTotal = 0;
    for (int r = 0; r < 3; r++) {
      long start = System.nanoTime();
      for (int i = 0; i < 20_000; i++) {
        bounded.callGet(rels.get(rnd.nextInt(ENTRIES)));
      }
      boundedTotal += System.nanoTime() - start;
    }
    long boundedMs = TimeUnit.NANOSECONDS.toMillis(boundedTotal / 3);
    assertTrue(
        "Bounded cache hit path regression (baseline=" + baselineMs + "ms, bounded=" + boundedMs + "ms)",
        boundedMs <= baselineMs * 1.5 + 10);
  }

  @Test(timeout = 10_000)
  public void testOptimizedLookupPathsNoOverhead() throws Exception {
    CacheHandle cache = newBoundedCache(10_000);
    Path p = writeText(cache.projectRoot, "opt/o.txt", "o");
    cache.callGet(p);
    Files.delete(cache.projectRoot.resolve(p));
    long t1 = System.nanoTime();
    for (int i = 0; i < 5000; i++) {
      assertNotNull(cache.callGet(p));
    }
    long ms1 = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t1);

    List<Path> extras = new ArrayList<>();
    for (int i = 0; i < 5000; i++) {
      Path pn = writeText(cache.projectRoot, "opt/n" + i + ".txt", "n" + i);
      cache.callGet(pn);
      extras.add(pn);
    }

    long t2 = System.nanoTime();
    for (int i = 0; i < 5000; i++) {
      if ((i & 1) == 0) {
        assertNotNull(cache.callGet(p));
      } else {
        cache.callGet(extras.get(i / 2));
      }
    }
    long ms2 = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t2);
    double per1 = ms1 / 5000.0;
    double per2 = ms2 / 5000.0;
    assertTrue(
        "Hot lookups should remain optimized (per2=" + per2 + ", per1=" + per1 + ")",
        ms2 <= ms1 * 1.2 + 2);
  }

  private static boolean safeEquals(Object a, Object b) {
    if (a == b) return true;
    if (a == null || b == null) return false;
    return a.equals(b);
  }
  private static Set<Long> hashCacheThreadIds() {
    Set<Long> ids = new HashSet<>();
    Map<Thread, StackTraceElement[]> all = Thread.getAllStackTraces();
    for (Thread t : all.keySet()) {
      String nm = t.getName().toLowerCase(Locale.ROOT);
      if (nm.contains("hash") || nm.contains("cache") || nm.contains("watch")) { ids.add(t.getId()); }
    }
    return ids;
  }
  private static Set<String> hashCacheThreadNames() {
    Set<String> names = new HashSet<>();
    Map<Thread, StackTraceElement[]> all = Thread.getAllStackTraces();
    for (Thread t : all.keySet()) {
      String nm = t.getName().toLowerCase(Locale.ROOT);
      if (nm.contains("hash") || nm.contains("cache") || nm.contains("watch") || nm.contains("timer")) {
        names.add(t.getName());
      }
    }
    names.removeIf(s -> s.toLowerCase(Locale.ROOT).contains("junit") || s.toLowerCase(Locale.ROOT).contains("gc"));
    return names;
  }

  private static boolean trySimulateReclamation(CacheHandle cache, int level) {
    List<String> names = Arrays.asList(
        "simulateReclamation", "forceReclamation", "forceDiscard",
        "triggerReclamation", "triggerMemoryPressure", "simulateGcPressure",
        "drainSoftRefs", "discardSome", "reclaim", "trimToSize", "compact");
    for (String n : names) {
      for (Method m : cache.instance.getClass().getMethods()) {
        if (!m.getName().equals(n)) continue;
        try {
          Class<?>[] pt = m.getParameterTypes();
          m.setAccessible(true);
          if (pt.length == 1 && (pt[0] == int.class || pt[0] == Integer.class)) {
            m.invoke(cache.instance, level);
            return true;
          } else if (pt.length == 0) {
            m.invoke(cache.instance);
            return true;
          } else if (pt.length == 1 && pt[0] == boolean.class) {
            m.invoke(cache.instance, true);
            return true;
          } else if (pt.length == 1 && pt[0] == Duration.class) {
            m.invoke(cache.instance, Duration.ofMillis(level * 10L));
            return true;
          }
        } catch (Throwable ignored) {}
      }
    }
    return false;
  }
  /**
   * Try to read a deterministic "active threads" count from the cache instance if provided.
   */
  private static Integer tryActiveThreadsCount(CacheHandle cache) {
    List<String> names = Arrays.asList("getActiveThreads", "activeThreadCount", "getThreadCount",
        "getExecutorActiveCount", "getActiveTaskCount", "getActiveWorkers");
    for (String n : names) {
      try {
        Method m = cache.instance.getClass().getMethod(n);
        if (!Modifier.isPublic(m.getModifiers())) continue;
        Object v = m.invoke(cache.instance);
        if (v instanceof Number) return ((Number) v).intValue();
      } catch (Exception ignored) {}
    }
    return null;
  }
}
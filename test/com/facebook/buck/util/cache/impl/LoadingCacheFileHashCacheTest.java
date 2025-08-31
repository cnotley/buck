package com.facebook.buck.util.cache.impl;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import com.facebook.buck.util.cache.FileHashCacheEngine;
import com.facebook.buck.util.cache.HashCodeAndFileType;
import com.google.common.collect.ImmutableList;
import com.google.common.hash.HashCode;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;

public class LoadingCacheFileHashCacheTest {

  @Test
  public void boundedCacheEvictsLeastRecentlyUsed() throws IOException {
    AtomicInteger counter = new AtomicInteger();
    FileHashCacheEngine.ValueLoader<HashCodeAndFileType> hashLoader =
        path -> HashCodeAndFileType.ofFile(HashCode.fromInt(counter.incrementAndGet()));
    FileHashCacheEngine.ValueLoader<Long> sizeLoader = path -> 1L;

    FileHashCacheEngine cache =
        LoadingCacheFileHashCache.createWithMaxEntries(hashLoader, sizeLoader, 1);
    Path p1 = Paths.get("a");
    Path p2 = Paths.get("b");
    cache.get(p1);
    cache.get(p2);
    assertNull(cache.getIfPresent(p1));
    assertNotNull(cache.getIfPresent(p2));
  }

  @Test
  public void invalidateAllRemovesPaths() throws IOException {
    AtomicInteger counter = new AtomicInteger();
    FileHashCacheEngine.ValueLoader<HashCodeAndFileType> hashLoader =
        path -> HashCodeAndFileType.ofFile(HashCode.fromInt(counter.incrementAndGet()));
    FileHashCacheEngine.ValueLoader<Long> sizeLoader = path -> 1L;
    FileHashCacheEngine cache =
        LoadingCacheFileHashCache.createWithMaxEntries(hashLoader, sizeLoader, 10);
    Path p1 = Paths.get("a");
    Path p2 = Paths.get("b");
    cache.get(p1);
    cache.get(p2);
    cache.invalidateAll(ImmutableList.of(p1, p2));
    assertNull(cache.getIfPresent(p1));
    assertNull(cache.getIfPresent(p2));
  }
}

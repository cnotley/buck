/*
 * Copyright (c) Facebook, Inc. and its affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.facebook.buck.util.cache.impl;

import com.facebook.buck.event.AbstractBuckEvent;
import com.facebook.buck.util.cache.FileHashCacheEngine;
import com.facebook.buck.util.cache.HashCodeAndFileType;
import com.facebook.buck.util.cache.JarHashCodeAndFileType;
import com.google.common.base.Preconditions;
import com.google.common.base.Throwables;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Maps;
import com.google.common.collect.Sets;
import com.google.common.hash.HashCode;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.ExecutionException;

class LoadingCacheFileHashCache implements FileHashCacheEngine {
  /** Cache for file hashes keyed by path. */
  private final LoadingCache<Path, HashCodeAndFileType> loadingCache;
  /** Cache for file sizes keyed by path. */
  private final LoadingCache<Path, Long> sizeCache;
  private final Map<Path, Set<Path>> parentToChildCache = new ConcurrentHashMap<>();

  /**
   * Strongly references basic file metadata (size, modified time) at time of last load for
   * detection of external changes.
   * The soft values held by {@link #loadingCache} may be cleared under memory pressure; the
   * metadata map allows us to detect when we need to recompute and invalidate stale entries.
   */
  private final ConcurrentMap<Path, FileAttributes> metadataCache = new ConcurrentHashMap<>();

  private static final class FileAttributes {
    final long size;
    final long lastModifiedMillis;

    FileAttributes(long size, long lastModifiedMillis) {
      this.size = size;
      this.lastModifiedMillis = lastModifiedMillis;
    }

    boolean matches(long size, long modifiedMillis) {
      return this.size == size && this.lastModifiedMillis == modifiedMillis;
    }
  }
  private final ValueLoader<Long> sizeLoader;

  private LoadingCacheFileHashCache(
      ValueLoader<HashCodeAndFileType> hashLoader,
      ValueLoader<Long> sizeLoader,
      long maximumEntries) {
    this.sizeLoader = sizeLoader;
    CacheBuilder<Object, Object> hashBuilder =
        CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors());
    CacheBuilder<Object, Object> sizeBuilder =
        CacheBuilder.newBuilder().concurrencyLevel(Runtime.getRuntime().availableProcessors());
    if (maximumEntries > 0) {
      hashBuilder.maximumSize(maximumEntries);
      sizeBuilder.maximumSize(maximumEntries);
    }
    // Allow values to be reclaimed on memory pressure.
    hashBuilder.softValues();
    sizeBuilder.softValues();
    loadingCache =
        hashBuilder.build(
            new CacheLoader<Path, HashCodeAndFileType>() {
              @Override
              public HashCodeAndFileType load(Path path) {
                HashCodeAndFileType value = hashLoader.load(path);
                updateParent(path);
                // Record metadata for change detection.
                recordMetadata(path, sizeLoader);
                return value;
              }
            });
    sizeCache =
        sizeBuilder.build(
            new CacheLoader<Path, Long>() {
              @Override
              public Long load(Path path) {
                long size = sizeLoader.load(path);
                updateParent(path);
                // Record metadata for change detection.
                recordMetadata(path, sizeLoader);
                return size;
              }
            });
  }

  private void updateParent(Path path) {
    Path parent = path.getParent();
    if (parent != null) {
      Set<Path> children =
          parentToChildCache.computeIfAbsent(parent, key -> Sets.newConcurrentHashSet());
      children.add(path);
    }
  }

  private void recordMetadata(Path path, ValueLoader<Long> loader) {
    try {
      long size = loader.load(path);
      long modified;
      try {
        modified = Files.getLastModifiedTime(path).toMillis();
      } catch (IOException e) {
        modified = -1L;
      }
      metadataCache.put(path, new FileAttributes(size, modified));
    } catch (RuntimeException e) {
      // If we can't compute metadata, don't prevent caching the value.
    }
  }

  public static FileHashCacheEngine createWithStats(
      ValueLoader<HashCodeAndFileType> hashLoader,
      ValueLoader<Long> sizeLoader,
      long maximumEntries) {
    return new StatsTrackingFileHashCacheEngine(
        new LoadingCacheFileHashCache(hashLoader, sizeLoader, maximumEntries), "old");
  }

  /**
   * Backwards-compatible creation method preserving previous unbounded semantics.
   */
  public static FileHashCacheEngine createWithStats(
      ValueLoader<HashCodeAndFileType> hashLoader, ValueLoader<Long> sizeLoader) {
    return createWithStats(hashLoader, sizeLoader, 0L);
  }

  @Override
  public void put(Path path, HashCodeAndFileType value) {
    loadingCache.put(path, value);
    updateParent(path);
    recordMetadata(path, sizeLoader);
  }

  @Override
  public void putSize(Path path, long value) {
    sizeCache.put(path, value);
    updateParent(path);
    recordMetadata(path, sizeLoader);
  }

  @Override
  public void invalidateWithParents(Path path) {
    Iterable<Path> pathsToInvalidate =
        Maps.filterEntries(
                loadingCache.asMap(),
                entry -> {
                  Objects.requireNonNull(entry);

                  // If we get a invalidation for a file which is a prefix of our current one, this
                  // means the invalidation is of a symlink which points to a directory (since
                  // events
                  // won't be triggered for directories).  We don't fully support symlinks, however,
                  // we do support some limited flows that use them to point to read-only storage
                  // (e.g. the `project.read_only_paths`).  For these limited flows to work
                  // correctly,
                  // we invalidate.
                  if (entry.getKey().startsWith(path)) {
                    return true;
                  }

                  // Otherwise, we want to invalidate the entry if the path matches it.  We also
                  // invalidate any directories that contain this entry, so use the following
                  // comparison to capture both these scenarios.
                  return path.startsWith(entry.getKey());
                })
            .keySet();
    for (Path pathToInvalidate : pathsToInvalidate) {
      invalidate(pathToInvalidate);
    }
  }

  @Override
  public void invalidate(Path path) {
    loadingCache.invalidate(path);
    sizeCache.invalidate(path);
    Set<Path> children = parentToChildCache.remove(path);

    // recursively invalidate all recorded children (underlying files and subfolders)
    if (children != null) {
      children.forEach(this::invalidate);
    }

    Path parent = path.getParent();
    if (parent != null) {
      Set<Path> siblings = parentToChildCache.get(parent);
      if (siblings != null) {
        siblings.remove(path);
      }
    }
  }

  @Override
  public HashCode get(Path path) throws IOException {
    Path normalized = path.normalize();
    // Detect if underlying file metadata has changed since last cache.
    FileAttributes attrs = metadataCache.get(normalized);
    if (attrs != null) {
      long currentSize = sizeLoader.load(normalized);
      long currentModified;
      try {
        currentModified = Files.getLastModifiedTime(normalized).toMillis();
      } catch (IOException e) {
        currentModified = -1L;
      }
      if (!attrs.matches(currentSize, currentModified)) {
        invalidate(normalized);
      }
    }
    try {
      HashCodeAndFileType code = loadingCache.get(normalized);
      return Preconditions.checkNotNull(code.getHashCode(),
          "Failed to find a HashCode for %s.", path);
    } catch (ExecutionException e) {
      Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
      throw new RuntimeException(e.getCause());
    }
  }

  @Override
  public HashCode getForArchiveMember(Path archiveRelativePath, Path memberPath)
      throws IOException {
    Path relativeFilePath = archiveRelativePath.normalize();
    // Ensure the jar has not changed underneath us.
    FileAttributes attrs = metadataCache.get(relativeFilePath);
    if (attrs != null) {
      long currentSize = sizeLoader.load(relativeFilePath);
      long currentModified;
      try {
        currentModified = Files.getLastModifiedTime(relativeFilePath).toMillis();
      } catch (IOException e) {
        currentModified = -1L;
      }
      if (!attrs.matches(currentSize, currentModified)) {
        invalidate(relativeFilePath);
      }
    }
    try {
      JarHashCodeAndFileType fileHashCodeAndFileType =
          (JarHashCodeAndFileType) loadingCache.get(relativeFilePath);
      HashCodeAndFileType memberHashCodeAndFileType =
          fileHashCodeAndFileType.getContents().get(memberPath);
      if (memberHashCodeAndFileType == null) {
        throw new NoSuchFileException(archiveRelativePath.toString());
      }

      return memberHashCodeAndFileType.getHashCode();
    } catch (ExecutionException e) {
      Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
      throw new RuntimeException(e.getCause());
    }
  }

  @Override
  public long getSize(Path relativePath) throws IOException {
    Path normalized = relativePath.normalize();
    try {
      return sizeCache.get(normalized);
    } catch (ExecutionException e) {
      Throwables.throwIfInstanceOf(e.getCause(), IOException.class);
      throw new RuntimeException(e.getCause());
    }
  }

  @Override
  public void invalidateAll() {
    loadingCache.invalidateAll();
    sizeCache.invalidateAll();
    parentToChildCache.clear();
    metadataCache.clear();
  }

  @Override
  public void invalidateAll(Iterable<? extends Path> paths) {
    loadingCache.invalidateAll(paths);
    sizeCache.invalidateAll(paths);
    for (Path path : paths) {
      parentToChildCache.remove(path);
      metadataCache.remove(path);
    }
  }

  @Override
  public ConcurrentMap<Path, HashCodeAndFileType> asMap() {
    return loadingCache.asMap();
  }

  @Override
  public HashCodeAndFileType getIfPresent(Path path) {
    return loadingCache.getIfPresent(path);
  }

  @Override
  public Long getSizeIfPresent(Path path) {
    return sizeCache.getIfPresent(path);
  }

  @Override
  public List<AbstractBuckEvent> getStatsEvents() {
    return Collections.emptyList();
  }
}

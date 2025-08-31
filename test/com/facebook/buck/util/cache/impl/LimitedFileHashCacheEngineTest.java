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

import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertNotNull;

import com.facebook.buck.io.filesystem.ProjectFilesystem;
import com.facebook.buck.io.filesystem.TestProjectFilesystems;
import com.facebook.buck.testutil.TemporaryPaths;
import com.facebook.buck.util.cache.HashCodeAndFileType;
import com.google.common.hash.HashCode;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.Rule;
import org.junit.Test;

public class LimitedFileHashCacheEngineTest {

  @Rule public TemporaryPaths tmp = new TemporaryPaths();

  @Test
  public void evictsLeastRecentlyUsedEntry() throws Exception {
    ProjectFilesystem fs = TestProjectFilesystems.createProjectFilesystem(tmp.getRoot());
    LimitedFileHashCacheEngine engine =
        new LimitedFileHashCacheEngine(
            fs,
            p -> HashCode.fromInt(p.hashCode()),
            p -> HashCodeAndFileType.ofFile(HashCode.fromInt(p.hashCode())),
            p -> 0L,
            2);

    Path a = Paths.get("a.txt");
    Path b = Paths.get("b.txt");
    Path c = Paths.get("c.txt");
    fs.touch(a);
    fs.touch(b);
    fs.touch(c);

    engine.put(a, HashCodeAndFileType.ofFile(HashCode.fromInt(1)));
    engine.put(b, HashCodeAndFileType.ofFile(HashCode.fromInt(2)));
    engine.put(c, HashCodeAndFileType.ofFile(HashCode.fromInt(3)));

    assertNull(engine.getIfPresent(a));
    assertNotNull(engine.getIfPresent(b));
    assertNotNull(engine.getIfPresent(c));
  }
}

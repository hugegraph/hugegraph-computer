/*
 * Copyright 2017 HugeGraph Authors
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements. See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership. The ASF
 * licenses this file to You under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

package com.baidu.hugegraph.computer.core.store.file;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.regex.Matcher;

import com.baidu.hugegraph.util.E;

public class HgkvDirImpl extends AbstractHgkvFile implements HgkvDir {

    private int segmentId;
    private final List<HgkvFile> segments;

    private HgkvDirImpl(String path) {
        this(path, null);
    }

    private HgkvDirImpl(String path, List<HgkvFile> segments) {
        super(path);
        this.segments = segments;
        this.segmentId = 0;
    }

    public static HgkvDir create(String path) throws IOException {
        File file = new File(path);
        E.checkArgument(!file.exists(),
                        "Directory already exists, path:%s", file.getPath());
        file.mkdirs();
        return new HgkvDirImpl(path);
    }

    public static HgkvDir open(String path) throws IOException {
        File file = new File(path);
        E.checkArgument(file.exists(), "Path not exists %s", file.getPath());
        E.checkArgument(file.isDirectory(), "Path is not directory %s",
                        file.getPath());
        return init(file);
    }

    private static HgkvDir init(File file) throws IOException {
        File[] files = file.listFiles(((dir, name) ->
                                        name.matches(HgkvFileImpl.NAME_REGEX)));
        assert files != null && files.length != 0;

        // Open segments
        List<HgkvFile> segments = segmentsFromFiles(files);

        // Set HgkvDir properties
        HgkvDirImpl hgkvDir = new HgkvDirImpl(file.getPath(), segments);
        hgkvDir.magic = HgkvFileImpl.MAGIC;
        hgkvDir.version = HgkvFileImpl.VERSION;
        hgkvDir.numEntries = segments.stream()
                                     .mapToLong(HgkvFile::numEntries)
                                     .sum();
        hgkvDir.max = segments.stream()
                              .map(HgkvFile::max)
                              .filter(Objects::nonNull)
                              .max(Comparable::compareTo)
                              .orElse(null);
        hgkvDir.min = segments.stream()
                              .map(HgkvFile::min)
                              .filter(Objects::nonNull)
                              .min(Comparable::compareTo)
                              .orElse(null);
        return hgkvDir;
    }

    private static List<HgkvFile> segmentsFromFiles(File[] files)
                                  throws IOException {
        List<HgkvFile> segments = new ArrayList<>();
        for (File file : files) {
            segments.add(HgkvFileImpl.open(file));
        }
        segments.sort((o1, o2) -> {
            int id1 = filePathToSegmentId(o1.path());
            int id2 = filePathToSegmentId(o2.path());
            return Integer.compare(id1, id2);
        });
        return segments;
    }

    private static int filePathToSegmentId(String path) {
        String fileName = path.substring(path.lastIndexOf(File.separator) + 1);
        Matcher matcher = HgkvFileImpl.FILE_NUM_PATTERN.matcher(fileName);
        E.checkState(matcher.find(), "Illegal file name [%s]", fileName);
        return Integer.parseInt(matcher.group());
    }

    @Override
    public List<HgkvFile> segments() {
        return this.segments;
    }

    @Override
    public String nextSegmentPath() {
        return this.path + File.separator + HgkvFileImpl.NAME_PREFIX +
               (++this.segmentId) + HgkvFileImpl.EXTEND_NAME;
    }
}
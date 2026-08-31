package main

import (
	"archive/tar"
	"archive/zip"
	"compress/gzip"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

var archiveTime = time.Date(2000, time.January, 1, 0, 0, 0, 0, time.UTC)

type archiveEntry struct {
	absPath string
	name    string
	info    fs.FileInfo
}

func main() {
	source := flag.String("source", "", "source directory")
	output := flag.String("output", "", "archive output path")
	format := flag.String("format", "", "zip or tar.gz")
	flag.Parse()
	if err := writeArchive(*source, *output, *format); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func collectEntries(source string) ([]archiveEntry, error) {
	root, err := filepath.Abs(strings.TrimSpace(source))
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Lstat(root)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("archive source must be a real directory")
	}
	entries := []archiveEntry{}
	err = filepath.WalkDir(root, func(candidate string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if candidate == root {
			return nil
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 || (!info.IsDir() && !info.Mode().IsRegular()) {
			return fmt.Errorf("archive input contains an unsupported entry: %s", entry.Name())
		}
		relative, err := filepath.Rel(root, candidate)
		if err != nil || relative == "." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
			return errors.New("archive input escaped its source root")
		}
		name := filepath.ToSlash(relative)
		if info.IsDir() {
			name += "/"
		}
		entries = append(entries, archiveEntry{absPath: candidate, name: name, info: info})
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].name < entries[right].name })
	return entries, nil
}

func normalizedMode(info fs.FileInfo) fs.FileMode {
	if info.IsDir() {
		return 0o755 | fs.ModeDir
	}
	if info.Mode()&0o111 != 0 {
		return 0o755
	}
	return 0o644
}

func copyRegularFile(writer io.Writer, entry archiveEntry) error {
	file, err := os.Open(entry.absPath)
	if err != nil {
		return err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(entry.info, opened) {
		return errors.New("archive input identity changed while packaging")
	}
	_, err = io.Copy(writer, file)
	return err
}

func openArchiveOutput(output string) (*os.File, func() error, error) {
	absOutput, err := filepath.Abs(output)
	if err != nil {
		return nil, nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absOutput))
	if err != nil {
		return nil, nil, err
	}
	file, err := root.OpenFile(filepath.Base(absOutput), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		_ = root.Close()
		return nil, nil, err
	}
	return file, root.Close, nil
}

func writeArchive(source, output, format string) (resultErr error) {
	entries, err := collectEntries(source)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return errors.New("archive source is empty")
	}
	if format != "zip" && format != "tar.gz" {
		return errors.New("archive format must be zip or tar.gz")
	}
	output = strings.TrimSpace(output)
	if output == "" {
		return errors.New("archive output path is required")
	}
	file, closeRoot, err := openArchiveOutput(output)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := closeRoot(); resultErr == nil {
			resultErr = closeErr
		}
	}()
	defer func() {
		if closeErr := file.Close(); resultErr == nil {
			resultErr = closeErr
		}
	}()

	if format == "zip" {
		writer := zip.NewWriter(file)
		for _, entry := range entries {
			header, err := zip.FileInfoHeader(entry.info)
			if err != nil {
				_ = writer.Close()
				return err
			}
			header.Name = entry.name
			header.SetModTime(archiveTime)
			header.SetMode(normalizedMode(entry.info))
			if !entry.info.IsDir() {
				header.Method = zip.Deflate
			}
			target, err := writer.CreateHeader(header)
			if err != nil {
				_ = writer.Close()
				return err
			}
			if !entry.info.IsDir() {
				if err := copyRegularFile(target, entry); err != nil {
					_ = writer.Close()
					return err
				}
			}
		}
		return writer.Close()
	}

	gzipWriter := gzip.NewWriter(file)
	gzipWriter.Header.ModTime = archiveTime
	gzipWriter.Header.OS = 255
	tarWriter := tar.NewWriter(gzipWriter)
	for _, entry := range entries {
		header, err := tar.FileInfoHeader(entry.info, "")
		if err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return err
		}
		header.Name = entry.name
		header.Mode = int64(normalizedMode(entry.info).Perm())
		header.ModTime = archiveTime
		header.AccessTime = archiveTime
		header.ChangeTime = archiveTime
		header.Uid = 0
		header.Gid = 0
		header.Uname = ""
		header.Gname = ""
		header.PAXRecords = nil
		if err := tarWriter.WriteHeader(header); err != nil {
			_ = tarWriter.Close()
			_ = gzipWriter.Close()
			return err
		}
		if !entry.info.IsDir() {
			if err := copyRegularFile(tarWriter, entry); err != nil {
				_ = tarWriter.Close()
				_ = gzipWriter.Close()
				return err
			}
		}
	}
	if err := tarWriter.Close(); err != nil {
		_ = gzipWriter.Close()
		return err
	}
	return gzipWriter.Close()
}

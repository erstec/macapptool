package main

import (
	"archive/zip"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/subcommands"

	"macapptool/internal/plist"
)

type payloadReader interface {
	io.Closer
	Next() (filename string, err error)
	Open() (f io.ReadCloser, err error)
}

type zipPayloadReader struct {
	r   *zip.ReadCloser
	pos int
}

func (r *zipPayloadReader) Close() error {
	return r.r.Close()
}

func (r *zipPayloadReader) Next() (string, error) {
	r.pos++
	if r.pos >= len(r.r.File) {
		return "", io.EOF
	}
	return r.r.File[r.pos].Name, nil
}

func (r *zipPayloadReader) Open() (io.ReadCloser, error) {
	if r.pos >= len(r.r.File) {
		return nil, io.EOF
	}
	return r.r.File[r.pos].Open()
}

func newZipPayloadReader(zr *zip.ReadCloser) payloadReader {
	return &zipPayloadReader{
		r:   zr,
		pos: -1,
	}
}

type stapleRequest struct {
	AppPath string
}

func commandDebugString(args ...string) string {
	var values []string
	expectPassword := false
	for _, v := range args {
		if expectPassword {
			values = append(values, strings.Repeat("Xx", 8)+"X")
			expectPassword = false
			continue
		}
		values = append(values, v)
	}
	return strings.Join(values, " ")
}

func writeCommandOutputOnDir(dir string, w io.Writer, args ...string) error {
	cmdString := commandDebugString(args...)
	if dir != "" {
		fmt.Printf("(%s) @%s\n", dir, cmdString)
	} else {
		fmt.Printf("@%s\n", cmdString)
	}
	cmd := exec.Command(args[0], args[1:]...)
	if dir != "" {
		cmd.Dir = dir
	}
	var (
		stdout io.Writer = os.Stdout
		stderr io.Writer = os.Stderr
	)
	if w != nil {
		stdout = io.MultiWriter(stdout, w)
		stderr = io.MultiWriter(stderr, w)
	}
	cmd.Stdin = os.Stdin
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func runCommandOnDir(dir string, args ...string) error {
	return writeCommandOutputOnDir(dir, nil, args...)
}

func writeCommandOutput(w io.Writer, args ...string) error {
	return writeCommandOutputOnDir("", w, args...)
}

func runCommand(args ...string) error {
	return runCommandOnDir("", args...)
}

func stapleAndVerify(zipFile string) error {
	// xcrun stapler staple
	dir, err := ioutil.TempDir("", "notarizer")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	p, canStaple, err := unzipPayload(zipFile, dir)
	if err != nil {
		return err
	}

	if canStaple {
		if err := runCommand("xcrun", "stapler", "staple", p); err != nil {
			return err
		}
	}

	if err := verifySignature(p); err != nil {
		return err
	}

	if canStaple {
		newZipPath, err := makeAppZip(p)
		if err != nil {
			return err
		}
		// Replace original zip with stapled one
		if err := os.Rename(newZipPath, zipFile); err != nil {
			return err
		}
	}
	return nil
}

func findPrimaryBundleID(payload string) (string, error) {
	var pr payloadReader
	switch strings.ToLower(filepath.Ext(payload)) {
	case ".zip":
		zr, err := zip.OpenReader(payload)
		if err != nil {
			return "", err

		}
		pr = newZipPayloadReader(zr)
	default:
		return "", fmt.Errorf("can't read payload with extension %q", filepath.Ext(payload))
	}
	count := 0
	var last string
	for {
		filename, err := pr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			return "", err
		}
		last = filename
		count++
		parts := strings.Split(filename, "/")
		if len(parts) == 3 &&
			filepath.Ext(parts[0]) == ".app" &&
			parts[1] == "Contents" &&
			parts[2] == "Info.plist" {

			ff, err := pr.Open()
			if err != nil {
				return "", err
			}
			defer ff.Close()
			plist, err := plist.New(ff)
			if err != nil {
				return "", err
			}
			bundleID, err := plist.BundleIdentifier()
			if err != nil {
				return "", err
			}
			return bundleID, nil
		}
	}
	if count == 1 && strings.IndexByte(last, '/') < 0 {
		// Single file zip, likely command line executable
		return "com.example." + last, nil
	}
	return "", errors.New("could not find Info.plist")
}

func staplePayload(req stapleRequest) error {
	stapleAndVerify(req.AppPath)
	return nil
}

func unzipPayload(payload string, outputDir string) (string, bool, error) {
	abs, err := filepath.Abs(payload)
	if err != nil {
		return "", false, err
	}
	if err := runCommandOnDir(outputDir, "unzip", abs); err != nil {
		return "", false, err
	}
	entries, err := ioutil.ReadDir(outputDir)
	if err != nil {
		return "", false, err
	}
	for _, v := range entries {
		name := v.Name()
		if filepath.Ext(name) == ".app" {
			fullPath := filepath.Join(outputDir, name)
			if st, err := os.Stat(fullPath); err == nil && st.IsDir() {
				return fullPath, true, nil
			}
		}
	}
	if len(entries) == 1 && filepath.Ext(entries[0].Name()) == "" && isExecutable(entries[0]) {
		// Single executable, can't be stapled
		return filepath.Join(outputDir, entries[0].Name()), false, nil
	}
	return "", false, fmt.Errorf("couldn't find any .app directories at %s", outputDir)
}

func makeAppZip(appDir string) (string, error) {
	basename := filepath.Base(appDir)
	ext := filepath.Ext(basename)
	nonExt := basename[:len(basename)-len(ext)]
	zipFile := nonExt + ".zip"
	dir := filepath.Dir(appDir)
	fmt.Printf("compressing %s to %s\n",
		filepath.Join(dir, basename), filepath.Join(dir, zipFile))

	if err := runCommandOnDir(dir, "zip", "-9", "-y", "-r", zipFile, basename); err != nil {
		return "", err
	}
	return filepath.Join(dir, zipFile), nil
}

func stapleFile(req stapleRequest) error {
	ext := filepath.Ext(req.AppPath)
	switch ext {
	case ".zip":
		return staplePayload(req)
	case ".app", "":
		appZip, err := makeAppZip(req.AppPath)
		if err != nil {
			return err
		}
		req.AppPath = appZip
		return staplePayload(req)
	default:
		return fmt.Errorf("can't staple app in %s format", ext)
	}
}

type stapleCmd struct {
}

func (*stapleCmd) Name() string {
	return "staple"
}

func (*stapleCmd) Synopsis() string {
	return "Staple an app bundle"
}

func (*stapleCmd) Usage() string {
	return `staple some.app
`
}

func (c *stapleCmd) Execute(_ context.Context, f *flag.FlagSet, _ ...interface{}) subcommands.ExitStatus {
	if f.NArg() != 1 {
		return subcommands.ExitUsageError
	}
	app := f.Args()[0]
	if err := c.stapleApp(app); err != nil {
		errPrintf("error stapling %s: %v\n", app, err)
		return subcommands.ExitFailure
	}
	return subcommands.ExitSuccess
}

func (c *stapleCmd) SetFlags(f *flag.FlagSet) {
}

func (c *stapleCmd) stapleApp(p string) error {
	req := stapleRequest{
		AppPath: p,
	}
	return stapleFile(req)
}

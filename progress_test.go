package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProgressBarRendersAndFinishes(t *testing.T) {
	var output bytes.Buffer
	bar := &progressBar{out: &output, enabled: true, width: 10}
	bar.Update("Reading input", 50)
	bar.Done()

	rendered := output.String()
	if !strings.Contains(rendered, "Reading input") {
		t.Fatalf("progress output missing label: %q", rendered)
	}
	if !strings.Contains(rendered, "50%") || !strings.Contains(rendered, "100%") {
		t.Fatalf("progress output missing percentages: %q", rendered)
	}
	if !strings.HasSuffix(rendered, "\n") {
		t.Fatalf("progress output should end with a newline: %q", rendered)
	}
}

func TestProgressBarBytesMapsToRange(t *testing.T) {
	var output bytes.Buffer
	bar := &progressBar{out: &output, enabled: true, width: 10}
	bar.Bytes("Reading input", 50, 100, 0, 20)

	if !strings.Contains(output.String(), "10%") {
		t.Fatalf("progress output = %q, want 10%%", output.String())
	}
}

func TestProgressBarDisabledWritesNothing(t *testing.T) {
	var output bytes.Buffer
	bar := &progressBar{out: &output, enabled: false, width: 10}
	bar.Update("Reading input", 50)
	bar.Done()

	if output.Len() != 0 {
		t.Fatalf("disabled progress output = %q, want empty", output.String())
	}
}

func TestNoProgressOption(t *testing.T) {
	options, err := parseArgs([]string{"--no-progress", "input.burp"})
	if err != nil {
		t.Fatal(err)
	}
	if !options.noProgress {
		t.Fatal("--no-progress was not parsed")
	}
}

func TestReadInputFileWithProgress(t *testing.T) {
	payload := bytes.Repeat([]byte("abc"), progressMinSize/3+1024)
	path := filepath.Join(t.TempDir(), "input.burp")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	bar := &progressBar{out: &output, enabled: true, width: 10}

	data, err := readInputFile(path, bar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatal("readInputFile returned different bytes")
	}
	if bar.percent != 20 {
		t.Fatalf("progress percent = %v, want reading to finish at 20", bar.percent)
	}
}

func TestReadBurpDataWithProgress(t *testing.T) {
	path, _ := buildTestProject(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	bar := &progressBar{out: &output, enabled: true, width: 10}
	warnings := []string{}

	raw, method, extra := readBurpData(data, 200_000, &warnings, bar)
	bar.Done()

	if method != "burp-heap" || extra == nil || len(raw) == 0 {
		t.Fatalf("method/extra/items = %q %#v %d", method, extra, len(raw))
	}
	if !strings.Contains(output.String(), "Burp extraction complete") {
		t.Fatalf("progress output = %q, want extraction stage", output.String())
	}
	if !strings.HasSuffix(output.String(), "\n") {
		t.Fatalf("progress output should end with a newline: %q", output.String())
	}
}

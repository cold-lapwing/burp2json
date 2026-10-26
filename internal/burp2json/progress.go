package burp2json

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const progressMinSize = 1 << 20 // 1 MiB

type progressBar struct {
	out     io.Writer
	enabled bool
	width   int
	label   string
	percent float64
	last    time.Time
}

func newProgressBar(enabled bool) *progressBar {
	return &progressBar{out: os.Stderr, enabled: enabled, width: 24}
}

func isTerminal(file *os.File) bool {
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func (p *progressBar) Update(label string, percent float64) {
	if p == nil || !p.enabled {
		return
	}
	if percent < 0 {
		percent = 0
	}
	if percent > 100 {
		percent = 100
	}
	labelChanged := label != p.label
	p.label = label
	p.percent = percent
	if !labelChanged && percent < 100 && !p.last.IsZero() &&
		time.Since(p.last) < 80*time.Millisecond {
		return
	}
	p.last = time.Now()
	p.render()
}

func (p *progressBar) Bytes(label string, done, total int64, start, end float64) {
	percent := start
	if total > 0 {
		percent = start + (end-start)*float64(done)/float64(total)
	}
	if percent < start {
		percent = start
	}
	if percent > end {
		percent = end
	}
	p.Update(label, percent)
}

func (p *progressBar) render() {
	filled := int(float64(p.width)*p.percent/100 + 0.5)
	if filled < 0 {
		filled = 0
	}
	if filled > p.width {
		filled = p.width
	}
	bar := strings.Repeat("=", filled) + strings.Repeat("-", p.width-filled)
	fmt.Fprintf(p.out, "\r%-24s [%s] %3.0f%%", fitProgressLabel(p.label, 24), bar, p.percent)
}

func fitProgressLabel(label string, width int) string {
	runes := []rune(label)
	if len(runes) > width {
		if width <= 3 {
			return string(runes[:width])
		}
		return string(runes[:width-3]) + "..."
	}
	return fmt.Sprintf("%-*s", width, label)
}

func (p *progressBar) Close() {
	if p == nil || !p.enabled {
		return
	}
	fmt.Fprint(p.out, "\n")
	p.enabled = false
}

func (p *progressBar) Done() {
	if p == nil || !p.enabled {
		return
	}
	if p.percent < 100 {
		p.Update(p.label, 100)
	}
	p.Close()
}

func progressEnabled(info os.FileInfo, noProgress bool) bool {
	return !noProgress && info.Size() >= progressMinSize && isTerminal(os.Stderr)
}

package main

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/iqhive/banner"
)

func TestFramesAreComputed(t *testing.T) {
	frames := build(0)
	var all strings.Builder
	for i := range frames {
		all.WriteString(banner.PlainText(&frames[i]))
	}
	for _, want := range []string{"=> lab   found=true", "=> campus   found=true", "=> default   found=true", "4 matching ancestors", "2 matching ancestors", "2001:db8:42::/48"} {
		if !strings.Contains(all.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestHeroArtifact(t *testing.T) {
	a, err := animation(0)
	if err != nil {
		t.Fatal(err)
	}
	again, err := animation(0)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, again) {
		t.Fatal("generation is not deterministic")
	}
	if banner.Duration(a.Frames) != 25*time.Second {
		t.Fatal("loop must be 25 seconds")
	}
	if a.StaticFrame != len(a.Frames)-2 || !a.Frames[len(a.Frames)-1].HiveLogo {
		t.Fatal("final cards")
	}
	for _, want := range []string{tagline, subline, install} {
		if !strings.Contains(banner.PlainText(&a.Frames[a.StaticFrame]), want) {
			t.Fatalf("static card missing %q", want)
		}
	}
	var svg bytes.Buffer
	if err := banner.WriteSVG(&svg, a); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile("../../docs/hero.svg")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(svg.Bytes(), committed) {
		t.Fatal("stale hero: run make hero-svg from the repository root")
	}
	if svg.Len() >= 500*1024 {
		t.Fatal("hero exceeds 500 KiB")
	}
	decoder := xml.NewDecoder(bytes.NewReader(svg.Bytes()))
	for {
		_, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if !strings.Contains(svg.String(), "<style>") || !strings.Contains(svg.String(), "prefers-reduced-motion") {
		t.Fatal("SVG animation/fallback missing")
	}
	var out, errs bytes.Buffer
	if run(nil, &out, &errs) != 0 {
		t.Fatal(errs.String())
	}
	if out.String() != banner.PlainText(&a.Frames[a.StaticFrame]) {
		t.Fatal("redirected output is not static card")
	}
}

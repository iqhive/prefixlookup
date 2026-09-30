package main

import (
	"fmt"
	"net/netip"

	"strings"
	"time"

	"github.com/iqhive/banner"
	"github.com/iqhive/prefixlookup/flatwalk"
	"github.com/iqhive/prefixlookup/prefixentry"
)

// All styling, wordmark layout, opening animation, SVG and playback live in banner.
// This file owns project text, deterministic demonstrations and reading holds.
type frame = banner.Frame

const (
	cols        = banner.Cols
	rows        = banner.Rows
	plain       = banner.Plain
	dim         = banner.Dim
	muted       = banner.Muted
	bright      = banner.Bright
	lit         = banner.Literal
	hot         = banner.Changed
	on          = banner.On
	off         = banner.Off
	bar         = banner.Bar
	prompt      = banner.Prompt
	caret       = banner.Caret
	full        = banner.Full
	shade       = banner.Shade
	projectName = "prefixlookup"
	tagline     = "Choose prefix indexes for your routing workload."
	subline     = "IPv4 + IPv6 · lookup / membership / traversal · workload-specific indexes"
	install     = "go get github.com/iqhive/prefixlookup/flatwalk"
)

var points = []string{"IPv4 + IPv6", "lookup / membership / traversal", "workload-specific indexes"}

type film struct {
	cur, card frame
	frames    []frame
}

func (m *film) cut(ms int) {
	f := m.cur
	f.Hold = time.Duration(ms) * time.Millisecond
	m.frames = append(m.frames, f)
}

// build executes the project fixtures. The seed affects decorative digits;
// iqhash also uses it for the real demonstrated digests.
func build(seed uint64) []frame {
	m := &film{}
	opening, card, err := banner.Opening(banner.Card{
		Word: projectName, Tagline: tagline, Points: points, Install: install,
		Wordmark: banner.WordmarkOptions{Seed: seed}, ReadHold: 2500 * time.Millisecond,
		TaglineReveal: banner.TaglineWithReveal, PointInterval: 200 * time.Millisecond,
	})
	if err != nil {
		panic(err)
	}
	m.frames, m.card = opening, card
	m.lookup()
	m.parents()
	m.cur = m.card
	m.cut(2500)
	m.cur = frame{HiveLogo: true}
	m.cur.Center(14, "IQ Hive", bright)
	m.cur.Center(16, "iqhive.com", muted)
	m.cut(1000)
	// Keep all scenes and quick motion; distribute extra reading time among
	// settled demonstration results and the final project card.
	extra := 25*time.Second - banner.Duration(m.frames)
	if extra < 0 {
		panic("hero: scene timing exceeds 25 seconds")
	}
	var holds []int
	for i := len(opening); i < len(m.frames)-1; i++ {
		if m.frames[i].Hold >= time.Second {
			holds = append(holds, i)
		}
	}
	for n, i := range holds {
		share := extra / time.Duration(len(holds)-n)
		m.frames[i].Hold += share
		extra -= share
	}
	return m.frames
}

// animation keeps generator failures visible instead of writing guessed output.
func animation(seed uint64) (a banner.Animation, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("hero fixture: %v", p)
		}
	}()
	frames := build(seed)
	a = banner.Animation{Frames: frames, StaticFrame: len(frames) - 2,
		Title:       projectName + " — README demonstration",
		Description: "Real IPv4 longest-prefix matches and IPv4/IPv6 ancestor traversal through flatwalk.",
		Command:     "make hero",
	}
	return a, a.Validate()
}

func fixture() *flatwalk.Table[string] {
	entries := []prefixentry.Entry[string]{}
	for i, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.42.0.0/16", "10.42.7.0/24", "2001:db8::/32", "2001:db8:42::/48"} {
		entries = append(entries, prefixentry.Entry[string]{Prefix: netip.MustParsePrefix(p), Value: []string{"default", "backbone", "campus", "lab", "v6 backbone", "v6 campus"}[i]})
	}
	t, err := flatwalk.New(entries)
	if err != nil {
		panic(err)
	}
	return t
}

func (m *film) routes(selected string) {
	m.cur.Text(4, 6, "PREFIX", muted)
	m.cur.Text(31, 6, "ROUTE", muted)
	for i, p := range []string{"0.0.0.0/0", "10.0.0.0/8", "10.42.0.0/16", "10.42.7.0/24"} {
		st := plain
		if p == selected {
			st = hot
		}
		m.cur.Text(4, 8+i*2, p, st)
		m.cur.Text(31, 8+i*2, []string{"default", "backbone", "campus", "lab"}[i], st)
		m.cur.Text(48, 8+i*2, strings.Repeat(string(full), i*8), on)
	}
}

func (m *film) lookup() {
	t := fixture()
	m.cur = frame{}
	m.cur.Text(2, 1, "01 / longest-prefix match", bright)
	m.cur.Text(2, 2, "The most specific matching route wins.", muted)
	m.routes("")
	input := "10.42.7.9"
	for i := 0; i <= len(input); i++ {
		m.cur.Clear(4, 5)
		m.cur.Text(2, 4, `Lookup("`+input[:i], lit)
		x := 2 + len(`Lookup("`) + i
		m.cur.Text(x, 4, " ", caret)
		m.cur.Cells[4][x] = banner.Cell{Rune: '▏', Style: caret}
		m.cut(80)
	}
	for _, q := range []struct{ ip, p string }{{input, "10.42.7.0/24"}, {"10.42.8.9", "10.42.0.0/16"}, {"203.0.113.9", "0.0.0.0/0"}} {
		m.cur.Clear(4, 5)
		m.cur.Text(2, 4, `Lookup("`+q.ip+`")`, lit)
		m.routes(q.p)
		v, ok := t.Lookup(netip.MustParseAddr(q.ip))
		m.cur.Clear(16, 19)
		m.cur.Text(2, 16, fmt.Sprintf("=> %s   found=%t", v, ok), bright)
		m.cur.Text(2, 18, "Bars show prefix length; the selected route is highlighted.", muted)
		m.cut(1150)
	}
}

func (m *film) parents() {
	t := fixture()
	m.cur = frame{}
	m.cur.Text(2, 1, "02 / walk the prefix hierarchy", bright)
	m.cur.Text(2, 2, "Follow matching routes from the most specific to the broadest.", muted)
	for _, ip := range []string{"10.42.7.9", "2001:db8:42::7"} {
		m.cur.Clear(4, 20)
		m.cur.Text(2, 4, `WalkParents("`+ip+`")`, lit)
		m.cut(350)
		n := 0
		t.WalkParents(netip.MustParseAddr(ip), func(_ flatwalk.RouteID, p netip.Prefix, v string) bool {
			y := 7 + n*2
			m.cur.Text(4+n*3, y, "└─ ", muted)
			m.cur.Text(7+n*3, y, p.String(), hot)
			m.cur.Text(39, y, v, plain)
			n++
			m.cur.Clear(17, 18)
			m.cur.Text(2, 17, fmt.Sprintf("%d matching ancestors", n), bright)
			m.cut(400)
			return true
		})
		m.cut(1150)
	}
}

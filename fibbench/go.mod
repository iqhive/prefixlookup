module github.com/iqhive/prefixlookup/fibbench

go 1.24.0

require (
	github.com/aromatt/netipds v0.1.9
	github.com/asergeyev/nradix v0.0.0-20220715161825-e451993e425c
	github.com/gaissmai/bart v0.29.0
	github.com/kentik/patricia v1.2.2
	github.com/phemmer/go-iptrie v0.0.0-20240326174613-ba542f5282c9
	github.com/yl2chen/cidranger v1.0.2
	tailscale.com v1.80.3
)

replace github.com/iqhive/prefixlookup => ..

require (
	github.com/iqhive/nradix v1.0.13
	github.com/iqhive/prefixlookup v0.0.0-00010101000000-000000000000
)

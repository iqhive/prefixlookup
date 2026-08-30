// Package routeid is just the route identifier type we pass around snapshots
//
// kept in its own package so we don't import a whole table just for a uint32 alias
package routeid

// ID is a route inside one immutable snapshot
// zero means none, and you must not keep these across generations, they get reused
type ID uint32

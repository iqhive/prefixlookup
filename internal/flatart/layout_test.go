package flatart

import "unsafe"

// unsafeSizeofNode is Sizeof with the cast TestNodeLayout keeps repeating
func unsafeSizeofNode() int   { return int(unsafe.Sizeof(node{})) }

// unsafeSizeofGroup is the 16-byte quarter-line we pin in TestNodeLayout
func unsafeSizeofGroup() int  { return int(unsafe.Sizeof(group{})) }

// unsafeOffsetOfHost is where the resolution set sits - must be the second line
func unsafeOffsetOfHost() int { return int(unsafe.Offsetof(node{}.host)) }

// unsafeSizeofStop is 80, not 128 - we dropped the child block
func unsafeSizeofStop() int   { return int(unsafe.Sizeof(stop{})) }

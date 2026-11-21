package xip

import "net/netip"

// addressIn returns the IPv4 address that labels carry. labels are the labels of a name below the zone apex in presentation form, each followed by its dot ("app.10-0-0-1."), and the empty string for the apex itself; letter case does not matter.
//
// Hyphens and dots cut labels into parts, and a backslash escapes the byte after it into the part it stands in. An address is four consecutive parts that are each a number from 0 to 255 without a leading zero, joined by three hyphens (dashed) or by three dots (dotted). The leftmost dashed address wins, and without one the leftmost dotted address.
func addressIn(labels string) (netip.Addr, bool) {
	var (
		run        octetRun
		part       partReader
		dotted     netip.Addr
		haveDotted bool
	)
	for i := 0; i <= len(labels); i++ {
		if i < len(labels) && labels[i] != '-' && labels[i] != '.' {
			if labels[i] == '\\' {
				part.escaped = true
				if i+1 < len(labels) {
					i++
				}
				continue
			}
			part.add(labels[i])
			continue
		}
		var separator byte
		if i < len(labels) {
			separator = labels[i]
		}
		value, isOctet := part.octet()
		part = partReader{}
		joiner, complete := run.push(value, isOctet, separator)
		if !complete {
			continue
		}
		if joiner == '-' {
			return netip.AddrFrom4(run.last), true
		}
		if !haveDotted {
			dotted, haveDotted = netip.AddrFrom4(run.last), true
		}
	}
	return dotted, haveDotted
}

// partReader reads one part byte by byte, keeping only what decides whether the part is an octet.
type partReader struct {
	digits      int
	value       int
	leadingZero bool
	escaped     bool
	other       bool
}

func (p *partReader) add(b byte) {
	if b < '0' || b > '9' {
		p.other = true
		return
	}
	if p.digits == 0 && b == '0' {
		p.leadingZero = true
	}
	// A part longer than three digits is no octet, and stopping the value here keeps it from overflowing on a long run of digits.
	if p.digits < 4 {
		p.value = p.value*10 + int(b-'0')
	}
	p.digits++
}

func (p *partReader) octet() (byte, bool) {
	if p.escaped || p.other || p.digits == 0 || p.digits > 3 || p.value > 255 || (p.leadingZero && p.digits > 1) {
		return 0, false
	}
	return byte(p.value), true
}

// octetRun follows the octets that end the parts read so far and are joined by one and the same separator.
type octetRun struct {
	length int
	joiner byte
	after  byte
	last   [4]byte
}

// push adds the next part and the separator that ends it, and reports the separator of the address the last four octets make, if they make one.
func (r *octetRun) push(value byte, isOctet bool, separator byte) (byte, bool) {
	joinedBy := r.after
	r.after = separator
	switch {
	case !isOctet:
		r.length = 0
		return 0, false
	case r.length == 0:
		r.length = 1
	case r.length == 1 || joinedBy != r.joiner:
		r.joiner = joinedBy
		r.length = 2
	default:
		r.length++
	}
	r.last = [4]byte{r.last[1], r.last[2], r.last[3], value}
	return r.joiner, r.length >= 4
}

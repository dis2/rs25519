// Package rs25519 implements 2-way Borromean Ring Signatures (BRS) for ed25519
package rs25519 // import "github.com/dis2/rs25519"

import "github.com/agl/ed25519/edwards25519"
import "crypto/sha512"
import "fmt"

// Usually the public key.
type Point struct {
	edwards25519.ExtendedGroupElement
}

// Projective coords point, result of scalarmult.
type PPoint struct {
	edwards25519.ProjectiveGroupElement
}

// Single secret key
type Scalar [32]byte

// Serialized BRS
type BRSignature []byte

// BRS byte buffer
func (brs BRSignature) Bytes() []byte {
	return []byte(brs)
}

// Create a scalar from given seed.
func HashToScalar(seed []byte) (s Scalar) {
	h := sha512.Sum512(seed)
	s = reduce(&h)
	return
}

func (brs BRSignature) String() string {
	return fmt.Sprintf("e: %x s[]: %x", brs.Bytes()[0:32], brs.Bytes()[32:])
}

// Unmarshal a point (public key)
func (P *Point) Unmarshal(b []byte) []byte {
	var buf [32]byte
	copy(buf[:], b)
	if !P.FromBytes(&buf) {
		return nil
	}
	return b[32:]
}

// Make a public child subkey using the given tweak.
func clamp(k *[32]byte) {
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64
}

func hash512(items ...[]byte) *[64]byte {
	h := sha512.New()
	for _, item := range items {
		h.Write(item)
	}
	var buf [64]byte
	h.Sum(buf[:0])
	return &buf
}

// Flip a point, this is faster than negating a scalar.
func (inp *Point) Negate() (outp Point) {
	outp = *inp
	edwards25519.FeNeg(&outp.X, &outp.X)
	edwards25519.FeNeg(&outp.T, &outp.T)
	return
}

// Negate a scalar mod L. TODO: make this less hideous.
func (a *Scalar) Negate() (res Scalar) {
	negone := Scalar{
		0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
		0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	}
	zero := Scalar{0}
	edwards25519.ScMulAdd(res.Bytes(), negone.Bytes(), a.Bytes(), zero.Bytes())
	return
}

// Encode point to a single coordinate. Does field inversion.
func (p *Point) Encode() (buf [32]byte) {
	ge := p.ExtendedGroupElement
	ge.ToBytes(&buf)
	return
}

func (p *Point) Marshal() []byte {
	buf := p.Encode()
	return buf[:]
}

// Encode point to a single coordinate. Does field inversion.
func (p *PPoint) Encode() (buf [32]byte) {
	ge := p.ProjectiveGroupElement
	ge.ToBytes(&buf)
	return
}

// aP + bG
func (P *Point) MulAdd(a, b *Scalar) (r PPoint) {
	edwards25519.GeDoubleScalarMultVartime(&r.ProjectiveGroupElement, a.Bytes(), &P.ExtendedGroupElement, b.Bytes())
	return
}

// A = aG
func (a *Scalar) MulBase() (A Point) {
	edwards25519.GeScalarMultBase(&A.ExtendedGroupElement, a.Bytes())
	return
}

// Convert representation from extended to projective (drop T)
func (P *Point) ToProjective() (PP PPoint) {
	P.ExtendedGroupElement.ToProjective(&PP.ProjectiveGroupElement)
	return
}

// res = a * b + c (mod L)
func (a *Scalar) MulAdd(b, c *Scalar) (res Scalar) {
	edwards25519.ScMulAdd(res.Bytes(), a.Bytes(), b.Bytes(), c.Bytes())
	return res
}

// Scalar to canonical bytes
func (k *Scalar) Bytes() *[32]byte {
	return (*[32]byte)(k)
}

// Before signing, a message and the public key list of the rings
// must be packed. This gives us final hash to BRSign, and serialized
// public key list. The packed result is what is to be transmitted
// to the verifier.
func BRPack(msg []byte, pub [][]Point) (hash [32]byte, pubs []byte) {
	h := sha512.New512_256()
	for _, ring := range(pub) {
		for _, v := range(ring) {
			buf := v.Marshal()
			h.Write(buf)
			pubs = append(pubs, buf...)
		}
	}
	h.Write(msg)
	h.Sum(hash[:0])
	return
}

// Verifier unpacks the public points and computes the hash which is to be
// verified. Returns nil points array if any can't be decoded.
func BRUnpack(msg, pubs []byte, m, n byte) (hash [32]byte, points [][]Point) {
	h := sha512.New512_256()
	points = make([][]Point, m)
	for i := byte(0); i < m; i++ {
		points[i] = make([]Point, n)
		for j := byte(0); j < n; j++ {
			if len(pubs) < 32 {
				return hash, nil
			}
			h.Write(pubs[0:32])
			pubs = points[i][j].Unmarshal(pubs)
			if pubs == nil {
				return hash, nil
			}
		}
	}
	h.Write(msg)
	h.Sum(hash[:0])
	return
}

// Have `n` rings, of `m` public keys each, held in `pub[m][n]`.
// For each ring, there must be one instance where the following holds:
//
// `pub[ring][indices[ring]] == getCorrespondingPublicKey(priv[ring])`
//
// All other entries in `pub[ring][...]` are indistuguishable public key
// forgeries. The forgery points should be still on curve.
//
// The blob in data[m*n*32] will be output in encrypted form as the 's' part
// of the signature. To retrieve original data[] from signature in BRVerify,
// one needs be in possesion of private keys the signature was crated with.
func BRSign(msghash *[32]byte, data []byte, pub [][]Point, priv []Scalar, indices []byte) (brs BRSignature) {
	n, m := byte(len(pub)), byte(len(pub[0]))

	r := make([]byte, len(pub)*len(pub[0])*32)

	xornoise(msghash, r, data, priv, indices)

	s := make([][][32]byte, n) // result
	k := make([]Scalar, n)     // clamped scalars from r
	saved := make([]byte, n)   // save bits from clamp
	E := sha512.New()

	for t := byte(0); t < n; t++ {
		s[t] = make([][32]byte, m)
		j := indices[t]
		k[t], saved[t] = clampSave(r[(t*m+j)*32:])
		z := k[t]

		ext := z.MulBase() // ext->proj
		e := chameleon(ext.ToProjective(), msghash, t, (j+1)%m, saved[t])
		for i := j + 1; i < m; i++ {
			sti := s[t][i][:]
			copy(sti, r[(t*m+i)*32:])
			z, w := clampSave(sti)
			pneg := pub[t][i].Negate()
			e = chameleon(pneg.MulAdd(&e, &z), msghash, t, (i+1)%m, w)
		}
		E.Write(e[:])
	}
	var e0hash [64]byte
	E.Sum(e0hash[:0])
	e0 := reduce(&e0hash)

	for t := byte(0); t < n; t++ {
		j := indices[t]
		e := e0
		for i := byte(0); i < j; i++ {
			sti := s[t][i][:]
			copy(sti, r[(t*m+i)*32:])
			z, w := clampSave(sti)
			pneg := pub[t][i].Negate()
			e = chameleon(pneg.MulAdd(&e, &z), msghash, t, (i+1)%m, w)
		}

		z := priv[t].MulAdd(&e, &k[t])
		if z[31]&0xf0 != 0 {
			panic("sig.s element over 2^252, something random isn't")
		}

		s[t][j] = z
		s[t][j][31] |= saved[t]
	}

	brs = append(brs, e0.Bytes()[:]...)
	for _, ring := range s {
		for _, ss := range ring {
			brs = append(brs, ss[:]...)
		}
	}

	return
}

func (brs BRSignature) load(pub [][]Point) (nret,mret byte, e [32]byte, s [][][32]byte) {
	p := brs.Bytes()
	n := len(pub)
	if n == 0 {
		return
	}
	m := len(pub[0])
	if m == 0 {
		return
	}
	if len(p) != m*n*32+32 {
		return
	}

	s = make([][][32]byte, n)

	copy(e[:], p[:32])
	for i, _ := range s {
		s[i] = make([][32]byte, m)
		for j, _ := range s[i] {
			p = p[32:]
			copy(s[i][j][:], p[:32])
		}
	}
	nret = byte(n)
	mret = byte(m)
	return
}

// Verify the signature. Both msghash and pub must be obtained via BRUnpack
// first.
func (brs BRSignature) Verify(msghash *[32]byte, pub [][]Point) bool {
	n,m,e0,brss := brs.load(pub)
	if brss == nil {
		return false
	}

	E := sha512.New()

	for t := byte(0); t < n; t++ {
		e := Scalar(e0)
		for i := byte(0); i < m; i++ {
			z := Scalar(brss[t][i])
			z[31] &= 0x0f
			w := brss[t][i][31] & 0xf0
			pneg := pub[t][i].Negate()
			e = chameleon(pneg.MulAdd(&e, &z), msghash, t, (i+1)%m, w)
		}
		E.Write(e[:])
	}

	var e1hash [64]byte
	E.Sum(e1hash[:0])
	if e0 != reduce(&e1hash) {
		return false
	}
	return true
}

// Recover the data blob from the signature.
func (brs BRSignature) Recover(msghash *[32]byte, pub [][]Point, priv []Scalar, indices []byte) []byte {
	n,m,e0,brss := brs.load(pub)
	if brss == nil {
		return nil
	}
	data := make([]byte, int(n)*int(m)*32)
	E := sha512.New()

	for t := byte(0); t < n; t++ {
		e := Scalar(e0)
		for i := byte(0); i < m; i++ {
			e = e.Negate()
			z := Scalar(brss[t][i])
			z[31] &= 0x0f
			w := brss[t][i][31] & 0xf0
			if i == indices[t] {
				k := e.MulAdd(&priv[t], &z)
				k[31] |= w
				copy(data[(t*m+i)*32:], k[:])
			} else {
				copy(data[(t*m+i)*32:], brss[t][i][:])
			}
			e = chameleon(pub[t][i].MulAdd(&e, &z), msghash, t, (i+1)%m, w)
		}

		E.Write(e[:])
	}
	xornoise(msghash, data, data, priv, indices)
	var e1hash [64]byte
	E.Sum(e1hash[:0])
	if e0 != reduce(&e1hash) {
		return nil
	}
	return data
}

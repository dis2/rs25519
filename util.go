package rs25519
import "github.com/agl/ed25519/edwards25519"
import "golang.org/x/crypto/salsa20/salsa"
import "crypto/sha512"

// chameleon hash input
func chameleon(R PPoint, msg *[32]byte, x, y, z byte) Scalar {
	rc := R.Encode()
	return reduce(hash512(rc[:], msg[:], []byte{x, y, z}))
}

func clampSave(in []byte) (out Scalar, w byte) {
	copy(out[:], in)
	out[31] &= 0xf
	w = in[31] & 0xf0
	return
}

func xornoise(msg *[32]byte, r []byte, data []byte /*pub [][]Point, */, priv []Scalar, indices []byte) {
	if data == nil {
		data = make([]byte, len(r))
	} else {
		dlen := len(data)
		if dlen < len(r) {
			data = append(data, make([]byte, len(r) - dlen)...)
		}
	}
	kh := sha512.New384()
	kh.Write(msg[:])
	for _, p := range priv {
		kh.Write(p.Bytes()[:])
		/*
			disabled - use msg commit instead
			for _, pu := range pub[i] {
				pb := pu.Encode()
				kh.Write(pb[:])
			}
		*/
	}
	kh.Write(indices)
	var key [32]byte
	var counter [16]byte
	hdata := kh.Sum(nil)
	copy(key[:], hdata)
	copy(counter[:], hdata[:32]) // hack to get 384bit key
	salsa.XORKeyStream(r, data, &counter, &key)
}

func reduce(in *[64]byte) (s Scalar) {
	edwards25519.ScReduce(s.Bytes(), in)
	return s
}



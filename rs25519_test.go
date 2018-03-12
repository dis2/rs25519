package rs25519
import "testing"
import "bytes"
import "math/rand"
//import "log"

// for simple troubleshooting
func Test1x1BRS(t *testing.T) {
	priv := []Scalar{HashToScalar([]byte("123"))}
	pub := [][]Point{[]Point{priv[0].MulBase()}}
	msg := []byte("hello")
	indices := []byte{0}

	h, _ := BRPack(msg, pub)
	tostore := []byte("The quick brown fox jumps over \x80")
	brs := BRSign(&h, tostore, pub, priv, indices)

	if !brs.Verify(&h, pub) {
		t.Fatal("verification failed")
	}

	recovered := brs.Recover(&h, pub, priv, indices)

	if !bytes.Equal(recovered, tostore) {
		t.Fatal("failed to ferry data")
	}
}

func TestUnpack(t *testing.T) {
	priv := []Scalar{HashToScalar([]byte("123"))}
	pub := [][]Point{[]Point{priv[0].MulBase()}}
	msg := []byte("hello")
	indices := []byte{0}

	// Signer
	h, packed := BRPack(msg, pub)
	tostore := []byte("The quick brown fox jumps over \x80")
	brs := BRSign(&h, tostore, pub, priv, indices)
	sig := brs.Bytes()

	// sig, msg, packed are to be transmitted

	// Verifier
	brs2 := BRSignature(sig)
	h2, pub2 := BRUnpack(msg, packed, 1, 1)
	if pub2 == nil {
		t.Fatal("unpack failed")
	}
	if !brs2.Verify(&h2, pub2) {
		t.Fatal("verification failed")
	}
}


func makeNM(n, m byte) (indices []byte, priv []Scalar, pub [][]Point) {
	indices = make([]byte, n)
	priv = make([]Scalar, n)
	pub = make([][]Point, n)
	for i := byte(0); i < n; i++ {
		// build forgeries
		pub[i] = make([]Point, m)
		for j := byte(0); j < m; j++ {
			dummy := HashToScalar([]byte{i,j,0xde,0xad})
			pub[i][j] = dummy.MulBase()
		}
		// make up a real private key
		priv[i] = HashToScalar([]byte{i})
		indices[i] = byte(rand.Intn(int(m)))
		pub[i][indices[i]] = priv[i].MulBase()
	}
	return
}

func Test100x100BRS(t *testing.T) {
	indices, priv, pub := makeNM(100,100)
	msg := []byte("hello")

	h, _ := BRPack(msg, pub)
	tostore := []byte("2aaaabbbbbbb")
	brs := BRSign(&h, tostore, pub, priv, indices)

	if !brs.Verify(&h, pub) {
		t.Fatal("verification failed")
	}

	recovered := brs.Recover(&h, pub, priv, indices)

	recovered = recovered[:len(tostore)]
	if !bytes.Equal(recovered, tostore) {
		t.Fatal("failed to ferry data")
	}
}



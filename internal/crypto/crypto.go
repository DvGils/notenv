// Package crypto wraps age. Cipher is satisfied by PassphraseCipher (MVP)
// and, post-MVP, a recipients-based cipher.
package crypto

type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

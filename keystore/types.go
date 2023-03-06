package keystore

type cipherparamsJSON struct {
	IV string `json:"iv"`
}

// ScryptParams
type ScryptParams struct {
	N          int    `json:"n"`
	R          int    `json:"r"`
	P          int    `json:"p"`
	DKeyLength int    `json:"dklen"`
	Salt       string `json:"salt"`
}

type cryptoJSON struct {
	Cipher       string           `json:"cipher"`
	CipherText   string           `json:"ciphertext"`
	CipherParams cipherparamsJSON `json:"cipherparams"`
	KDF          string           `json:"kdf"`
	KDFParams    ScryptParams     `json:"kdfparams"`
	MAC          string           `json:"mac"`
}

type encryptedKeyJSON struct {
	Address string     `json:"address"`
	Crypto  cryptoJSON `json:"crypto"`
	ID      string     `json:"id"`
	Version int        `json:"version"`
}

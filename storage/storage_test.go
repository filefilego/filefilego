package storage

import (
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/filefilego/filefilego/common"
	"github.com/filefilego/filefilego/database"
	"github.com/stretchr/testify/assert"
	"github.com/syndtr/goleveldb/leveldb"
)

func TestNew(t *testing.T) {
	t.Parallel()
	db, err := leveldb.OpenFile("storagetest.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)

	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("storagetest.db")
		os.RemoveAll("/tmp/invalidpathffg")
	})
	cases := map[string]struct {
		db                  database.Database
		storagePath         string
		enabled             bool
		adminToken          string
		totalMerkleSegments int
		expErr              string
	}{
		"no database": {
			expErr: "db is nil",
		},
		"no storagePath": {
			db:     driver,
			expErr: "storagePath is empty",
		},
		"no adminToken": {
			db:          driver,
			storagePath: "/tmp/",
			expErr:      "adminToken is empty",
		},
		"zero merkle segments": {
			db:          driver,
			storagePath: "/tmp/",
			adminToken:  "12345",
			expErr:      "merkle tree total segments is zero",
		},
		"success": {
			db:                  driver,
			storagePath:         "/tmp/invalidpathffg/",
			adminToken:          "12345",
			totalMerkleSegments: 1024,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			storage, err := New(tt.db, tt.storagePath, tt.enabled, tt.adminToken, tt.totalMerkleSegments)
			if tt.expErr != "" {
				assert.Nil(t, storage)
				assert.EqualError(t, err, tt.expErr)
			} else {
				assert.NotNil(t, storage)
			}
		})
	}
}

func TestStorageMethods(t *testing.T) {
	db, err := leveldb.OpenFile("storagetest2.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	storagePath := "/tmp/invalidpathffg2"
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("storagetest2.db")
		os.RemoveAll(storagePath)
	})
	storage, err := New(driver, storagePath, false, "admintoken", 1024)
	assert.NoError(t, err)
	assert.Equal(t, false, storage.Enabled())
	assert.Equal(t, storagePath, storage.StoragePath())

	storage.SetEnabled(true)
	assert.Equal(t, true, storage.Enabled())

	subfolder, err := storage.CreateSubfolders()
	assert.NoError(t, err)
	assert.Equal(t, true, common.DirExists(subfolder))

	// retry to create the same subfolder
	subfolder, err = storage.CreateSubfolders()
	assert.NoError(t, err)
	assert.Equal(t, true, common.DirExists(subfolder))

	// save invalid access token
	token := AccessToken{}
	err = storage.SaveToken(token)
	assert.EqualError(t, err, "invalid access token")

	// save a valid access token
	tokenVal := "123456"
	token = AccessToken{
		AccessType: UserAccess,
		Token:      tokenVal,
		ExpiresAt:  time.Now().Add(time.Hour * tokenAccessHours).Unix(),
	}

	err = storage.SaveToken(token)
	assert.NoError(t, err)

	// verify access token is stored
	found, tk, err := storage.CanAccess(tokenVal)
	assert.Equal(t, true, found)
	assert.NoError(t, err)
	assert.Equal(t, token, tk)

	// get invalid access token
	found, tk, err = storage.CanAccess("invalidtoken2222")
	assert.Equal(t, false, found)
	assert.EqualError(t, err, "failed to get value: leveldb: not found")
	assert.Equal(t, AccessToken{}, tk)

	// empty access token
	found, tk, err = storage.CanAccess("")
	assert.Equal(t, false, found)
	assert.EqualError(t, err, "token is empty")
	assert.Equal(t, AccessToken{}, tk)

	// expired access token
	token2Val := "9999999"
	token2 := AccessToken{
		AccessType: UserAccess,
		Token:      token2Val,
		ExpiresAt:  time.Now().Add(-time.Hour * tokenAccessHours).Unix(),
	}
	err = storage.SaveToken(token2)
	assert.NoError(t, err)
	found, tk, err = storage.CanAccess(token2Val)
	assert.Equal(t, false, found)
	assert.EqualError(t, err, "access token is expired")
	assert.Equal(t, AccessToken{}, tk)

	// save file metadata
	node1Hash := "nodehash1"

	// invalid file metadata
	err = storage.SaveFileMetadata(node1Hash, "wdasd", FileMetadata{})
	assert.EqualError(t, err, "invalid file metadata")

	// valid file metadata
	fileHash := "filehash123"
	node1Metadata := FileMetadata{
		MerkleRootHash: "0x0123",
		Hash:           fileHash,
		FilePath:       "/tmp/filename",
		Size:           123,
	}
	err = storage.SaveFileMetadata(node1Hash, fileHash, node1Metadata)
	assert.NoError(t, err)

	// get file metadata
	// invalid
	fileMetadata, err := storage.GetFileMetadata("")
	assert.EqualError(t, err, "file hash is empty")
	assert.Equal(t, FileMetadata{}, fileMetadata)

	// valid
	fileMetadata, err = storage.GetFileMetadata(fileHash)
	assert.NoError(t, err)
	assert.Equal(t, node1Metadata, fileMetadata)

	// given file hash we retrieve the nodehash
	// empty filehash
	retrivedNodeHash, found := storage.GetNodeHashFromFileHash("")
	assert.Equal(t, false, found)
	assert.Equal(t, "", retrivedNodeHash)

	// non existing filehash
	retrivedNodeHash, found = storage.GetNodeHashFromFileHash("34423u4234")
	assert.Equal(t, false, found)
	assert.Equal(t, "", retrivedNodeHash)

	// valid filehash
	retrivedNodeHash, found = storage.GetNodeHashFromFileHash(fileHash)
	assert.Equal(t, true, found)
	assert.Equal(t, node1Hash, retrivedNodeHash)
}

func TestAuthenticateHandler(t *testing.T) {
	db, err := leveldb.OpenFile("storagetestauth.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	storagePath := "/tmp/storagetestuploading"
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("storagetestauth.db")
		os.RemoveAll(storagePath)
	})
	storage, err := New(driver, storagePath, true, "admintoken", 1024)
	assert.NoError(t, err)
	handler := http.HandlerFunc(storage.Authenticate)

	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// invalid token
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusForbidden, rr.Code)
	expected := `{"error": "token is empty"}`
	if rr.Body.String() != expected {
		t.Errorf("handler returned unexpected body: got %v want %v",
			rr.Body.String(), expected)
	}

	// add authorition header
	req, err = http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	req.Header.Set("Authorization", "admintoken")
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	type tokenResponse struct {
		Token string `json:"token"`
	}
	data := tokenResponse{}
	err = json.Unmarshal(rr.Body.Bytes(), &data)
	assert.NoError(t, err)
	assert.NotEmpty(t, data.Token)
	assert.Equal(t, 122, len(data.Token))

	// verify the access token in the http response exists in storage
	can, accTok, err := storage.CanAccess(data.Token)
	assert.Equal(t, true, can)
	assert.NoError(t, err)
	assert.Equal(t, accTok.Token, data.Token)
}

func TestUploadHandler(t *testing.T) {
	db, err := leveldb.OpenFile("storagetestuploading.db", nil)
	assert.NoError(t, err)
	driver, err := database.New(db)
	assert.NoError(t, err)
	storagePath := "/tmp/storagetestuploading"
	t.Cleanup(func() {
		db.Close()
		os.RemoveAll("storagetestuploading.db")
		os.RemoveAll(storagePath)
	})
	storage, err := New(driver, storagePath, true, "admintoken", 1024)
	assert.NoError(t, err)
	handler := http.HandlerFunc(storage.Authenticate)

	req, err := http.NewRequest("POST", "/auth", nil)
	if err != nil {
		t.Fatal(err)
	}

	// get an access token
	rr := httptest.NewRecorder()
	req.Header.Set("Authorization", "admintoken")
	handler.ServeHTTP(rr, req)
	assert.Equal(t, http.StatusOK, rr.Code)
	type tokenResponse struct {
		Token string `json:"token"`
	}
	data := tokenResponse{}
	err = json.Unmarshal(rr.Body.Bytes(), &data)
	assert.NoError(t, err)
	assert.NotEmpty(t, data.Token)

	pr, pw := io.Pipe()
	writer := multipart.NewWriter(pw)
	go func() {
		defer writer.Close()
		nodeWriter, err := writer.CreateFormField("node_hash")
		if err != nil {
			t.Error(err)
		}
		_, err = nodeWriter.Write([]byte("nodehash123"))
		if err != nil {
			t.Error(err)
		}

		part, err := writer.CreateFormFile("file", "random.txt")
		if err != nil {
			t.Error(err)
		}
		_, err = part.Write([]byte("sometext"))
		if err != nil {
			t.Error(err)
		}
	}()

	request := httptest.NewRequest("POST", "/", pr)
	request.Header.Add("Content-Type", writer.FormDataContentType())
	request.Header.Set("Authorization", data.Token)

	response := httptest.NewRecorder()
	storage.ServeHTTP(response, request)
	assert.Equal(t, http.StatusOK, rr.Code)
	type fileUploadResponse struct {
		FileHash       string `json:"file_hash"`
		MerkleRootHash string `json:"merkle_root_hash"`
		Size           int    `json:"size"`
	}
	fileUploaded := fileUploadResponse{}
	err = json.Unmarshal(response.Body.Bytes(), &fileUploaded)
	assert.NoError(t, err)
	assert.Equal(t, 8, fileUploaded.Size)
	// the merkle tree root hash is 32 bytes and 66 in hex encoded.
	assert.Len(t, fileUploaded.MerkleRootHash, 66)

	fileMetadata, err := storage.GetFileMetadata(fileUploaded.FileHash)
	assert.NoError(t, err)

	if _, err := os.Stat(fileMetadata.FilePath); os.IsNotExist(err) {
		t.Errorf("Expected file %s to exist", fileMetadata.FilePath)
	}
}

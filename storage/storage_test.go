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
	"github.com/filefilego/filefilego/common/hexutil"
	"github.com/filefilego/filefilego/crypto"
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
		peerID              string
		allowFeesOverride   bool
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
		"no peerID": {
			db:                  driver,
			storagePath:         "/tmp/invalidpathffg/",
			adminToken:          "12345",
			totalMerkleSegments: 1024,
			expErr:              "peerID is empty",
		},
		"success": {
			db:                  driver,
			storagePath:         "/tmp/invalidpathffg/",
			adminToken:          "12345",
			totalMerkleSegments: 1024,
			peerID:              "DKldkldk",
			allowFeesOverride:   false,
		},
	}

	for name, tt := range cases {
		tt := tt
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			storage, err := New(tt.db, tt.storagePath, tt.enabled, tt.adminToken, tt.totalMerkleSegments, tt.peerID, tt.allowFeesOverride)
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
	_, err = common.WriteToFile([]byte("hello world"), "testfile.txt")
	assert.NoError(t, err)
	t.Cleanup(func() {
		db.Close()
		os.Remove("exported_files.json")
		os.Remove("testfile.txt")
		os.RemoveAll("storagetest2.db")
		os.RemoveAll(storagePath)
	})
	storage, err := New(driver, storagePath, false, "admintoken", 1024, "16Uiu2HAmTFHgmWhmcned8QTH3t38WkMBTeFU5xLRgsuwMTjTUe6k", false)
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

	// invalid file metadata
	err = storage.SaveFileMetadata("wdasd", "16Uiu2HAmTFHgmWhmcned8QTH3t38WkMBTeFU5xLRgsuwMTjTUe6k", FileMetadata{})
	assert.EqualError(t, err, "invalid file metadata")

	// valid file metadata
	sha1OfFile, err := crypto.Sha1File("testfile.txt")
	assert.NoError(t, err)
	fileHash := sha1OfFile
	node1Metadata := FileMetadata{
		FileName:       "testfile.txt",
		MerkleRootHash: "0x0123",
		Hash:           fileHash,
		FilePath:       "testfile.txt",
		Size:           123,
		Timestamp:      time.Now().Unix(),
	}
	err = storage.SaveFileMetadata(fileHash, "16Uiu2HAmTFHgmWhmcned8QTH3t38WkMBTeFU5xLRgsuwMTjTUe6k", node1Metadata)
	assert.NoError(t, err)

	// get file metadata
	// invalid
	fileMetadata, err := storage.GetFileMetadata("", "")
	assert.EqualError(t, err, "file hash is empty")
	assert.Equal(t, FileMetadata{}, fileMetadata)

	// valid
	fileMetadata, err = storage.GetFileMetadata(fileHash, "16Uiu2HAmTFHgmWhmcned8QTH3t38WkMBTeFU5xLRgsuwMTjTUe6k")
	assert.NoError(t, err)
	assert.Equal(t, node1Metadata, fileMetadata)

	uploadedData, totalCount, err := storage.ListFiles(0, 100, "asc")
	assert.NoError(t, err)
	assert.Len(t, uploadedData, 1)
	assert.Equal(t, uint64(1), totalCount)

	exportedFiles, err := storage.ExportFiles()
	assert.NoError(t, err)
	encodedBytes, err := json.Marshal(exportedFiles)
	assert.NoError(t, err)
	_, err = common.WriteToFile(encodedBytes, "exported_files.json")
	assert.NoError(t, err)
	// delete the file
	err = storage.DeleteFileFromDB(uploadedData[0].Key)
	assert.NoError(t, err)
	uploadedData, totalCount, err = storage.ListFiles(0, 100, "asc")
	assert.NoError(t, err)
	assert.Len(t, uploadedData, 0)
	assert.Equal(t, uint64(0), totalCount)

	// delete the file metadata now
	err = storage.DeleteFileMetadata(fileHash, "16Uiu2HAmTFHgmWhmcned8QTH3t38WkMBTeFU5xLRgsuwMTjTUe6k")
	assert.NoError(t, err)

	// read again the files
	exportedFiles, err = storage.ExportFiles()
	assert.NoError(t, err)
	assert.Len(t, exportedFiles, 0)

	n, err := storage.ImportFiles("exported_files.json")
	assert.Equal(t, 1, n)
	assert.NoError(t, err)
	exportedFiles, err = storage.ExportFiles()
	assert.NoError(t, err)
	assert.Len(t, exportedFiles, 1)
}

func TestCreateStorageAccessTokenHandler(t *testing.T) {
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
	storage, err := New(driver, storagePath, true, "admintoken", 1024, "peerID", false)
	assert.NoError(t, err)
	handler := http.HandlerFunc(storage.CreateStorageAccessToken)

	req, err := http.NewRequest("POST", "/storage/access_tokens", nil)
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
	req, err = http.NewRequest("POST", "/storage/access_tokens", http.NoBody)
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

	// do the introspection
	handler2 := http.HandlerFunc(storage.IntrospectAccessToken)
	req2, err := http.NewRequest("POST", "/storage/introspect", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	req2.Header.Set("Authorization", accTok.Token)
	rr2 := httptest.NewRecorder()
	handler2.ServeHTTP(rr2, req2)
	assert.Equal(t, http.StatusOK, rr2.Code)
	introspected := AccessToken{}
	err = json.Unmarshal(rr2.Body.Bytes(), &introspected)
	assert.NoError(t, err)

	assert.NotEmpty(t, introspected.Token)
	assert.NotEmpty(t, introspected.ExpiresAt)
	assert.NotEmpty(t, introspected.AccessType)
	assert.Equal(t, accTok.Token, introspected.Token)
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
	storage, err := New(driver, storagePath, true, "admintoken", 1024, "peerID", false)
	assert.NoError(t, err)
	handler := http.HandlerFunc(storage.CreateStorageAccessToken)

	req, err := http.NewRequest("POST", "/storage/access_tokens", http.NoBody)
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
		ownerPubKey, err := writer.CreateFormField("public_key_owner")
		if err != nil {
			t.Error(err)
		}
		_, err = ownerPubKey.Write([]byte{2})
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
		FileName       string `json:"file_name"`
		FileHash       string `json:"file_hash"`
		MerkleRootHash string `json:"merkle_root_hash"`
		Size           int    `json:"size"`
	}
	fileUploaded := fileUploadResponse{}
	err = json.Unmarshal(response.Body.Bytes(), &fileUploaded)
	assert.NoError(t, err)
	assert.Equal(t, 8, fileUploaded.Size)
	assert.Equal(t, "random.txt", fileUploaded.FileName)
	// the merkle tree root hash is 32 bytes and 66 in hex encoded.
	assert.Len(t, fileUploaded.MerkleRootHash, 66)

	fileMetadata, err := storage.GetFileMetadata(fileUploaded.FileHash, "peerID")
	assert.NoError(t, err)
	// check if owner is equal to the byte supplied above
	assert.Equal(t, hexutil.Encode([]byte{2}), fileMetadata.PublicKeyOwner)
	if _, err := os.Stat(fileMetadata.FilePath); os.IsNotExist(err) {
		t.Errorf("Expected file %s to exist", fileMetadata.FilePath)
	}

	uploadedData, totalCount, err := storage.ListFiles(0, 100, "asc")
	assert.NoError(t, err)
	assert.Len(t, uploadedData, 1)
	assert.Equal(t, uint64(1), totalCount)
}

func TestValidateFileName(t *testing.T) {
	validFileNames := []string{
		"file.txt",
		"my-file.jpg",
		"12345.txt",
		"file with spaces.txt",
		"file with_underscores.txt",
		"file.with.dots.txt",
		"my file.jpg",
		"file.txt$",
		"file.",
	}

	invalidFileNames := []string{
		"file<name>.txt",
		"file:name.txt",
		"file\"name\".txt",
		"file/name.txt",
		"file\\name.txt",
		"file|name.txt",
		"file?name.txt",
		"file*name.txt",
		"file\x00name.txt",
	}

	for _, fileName := range validFileNames {
		if !validateFileName(fileName) {
			t.Errorf("'%s' should be a valid file name", fileName)
		}
	}

	for _, fileName := range invalidFileNames {
		if validateFileName(fileName) {
			t.Errorf("'%s' should be an invalid file name", fileName)
		}
	}
}

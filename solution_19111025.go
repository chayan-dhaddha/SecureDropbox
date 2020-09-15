package main

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/sarkarbidya/CS628-assn1/userlib

	"fmt"

	"github.com/sarkarbidya/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...

	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// test
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

var configBlockSize = 4096 //Do not modify this variable

//setBlockSize - sets the global variable denoting blocksize to the passed parameter. This will be called only once in the beginning of the execution
func setBlockSize(blocksize int) {
	configBlockSize = blocksize
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

//User : User structure used to store the user information
type User struct {
	Username   string
	Uuid       []byte
	Key        []byte
	PrivateKey *userlib.PrivateKey
	FileRecord map[string][]byte
	HashKey    []byte
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

func EncryptData(data []byte, key []byte) (cipherdata []byte) {
	strUs := string(data)
	ciphertext := make([]byte, userlib.BlockSize+len(strUs))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(strUs))
	return ciphertext
}

func ComputeHashValue(ciphertext []byte, Hashkey []byte) (macd []byte) {
	mac := userlib.NewHMAC(Hashkey)
	mac.Write(ciphertext)
	macd = mac.Sum(nil)
	return macd

}

// StoreFile : function used to create a  file
// It should store the file in blocks only if length
// of data []byte is a multiple of the blocksize; if
// this is not the case, StoreFile should return an error.
func (userdata *User) StoreFile(filename string, data []byte) (err error) {

	if len(userdata.FileRecord[filename]) != 0 {
		return errors.New("FAILURE:: STORE FILE :: FILE WITH SAME NAME ALREADY EXISTED")
	}
	//fmt.Println("---------------in store file-----------------------")
	if len(data)%configBlockSize != 0 {
		return errors.New("File Not in Multiple of Block Size")

	}
	// CREATING A SHARING RECORD AND CREATE ITS UID
	var shareRecord sharingRecord
	shareRecord.Offset = 0
	//Suid := userlib.Argon2Key([]byte(userdata.Uuid), []byte(filename), 64)
	Suid := userlib.RandomBytes(64)
	Suuid := Suid[0:32]
	Skey := Suid[32:48]
	SHashkey := Suid[48:64]

	// STORING SHARING RECORD UID IN USER DATA STRUCTURE
	userdata.FileRecord[filename] = Suid

	iterate := len(data) / configBlockSize
	startIndex := 0
	endIndex := configBlockSize
	// ITERATING FOR EACH BLOCK DATA
	for i := 0; i < iterate; i++ {
		//fmt.Println(i)
		// Creating Memory for BlockData and Storing
		BlockData := make([]byte, configBlockSize)
		BlockData = data[startIndex:endIndex]
		startIndex = endIndex
		endIndex = endIndex + configBlockSize

		// Creating buid,key and hashKey for each Block
		uid := userlib.RandomBytes(64)
		buid := uid[0:32]
		key := uid[32:48]
		hashKey := uid[48:64]

		// Storing Blockuuid in Sharing Record
		shareRecord.Blockuuid = append(shareRecord.Blockuuid, uid)
		shareRecord.Offset++

		// Encrypting the data
		ciphertext := EncryptData(BlockData, key)

		// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
		macd := ComputeHashValue(ciphertext, hashKey)

		// APPENDED CIPHERTEXT WITH MACVALUE
		Data := append(ciphertext, macd...)

		// Marshalling the data and then storing it in datastore
		marshalledData, e1 := json.Marshal(Data)
		if e1 != nil {
			return errors.New("FAILURE:: STORE FILE --- JSON OBJECT")
		}
		userlib.DatastoreSet(string(buid), marshalledData)
	}

	// FOR SHARING RECORD ENCRYPT + HASHVALUE + MARSHALL
	us, e2 := json.Marshal(shareRecord)
	if e2 != nil {
		return errors.New("FAILURE:: STORE FILE --- JSON OBJECT")
	}
	ciphertext := EncryptData(us, Skey)

	// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
	macd := ComputeHashValue(ciphertext, SHashkey)

	// APPENDED CIPHERTEXT WITH MACVALUE
	Data := append(ciphertext, macd...)

	// Marshalling the data and then storing it in datastore
	marshalledData, e3 := json.Marshal(Data)
	if e3 != nil {
		return errors.New("FAILURE:: STORE FILE --- JSON OBJECT")
	}
	userlib.DatastoreSet(string(Suuid), marshalledData)

	return nil

}

//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need. The length of data []byte must be a multiple of
// the block size; if it is not, AppendFile must return an error.
// AppendFile : Function to append the file
func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	//fmt.Println("---------------in append file-----------------------")
	if len(userdata.FileRecord[filename]) == 0 {
		return errors.New("FAILURE:: APPENDFILE:: FILENAME NOT FOUND")
	}
	if len(data)%configBlockSize != 0 {
		return errors.New("FAILURE:: APPENDED FILE ---- File Not in Multiple of Block Size")

	}
	// SHARING UID RECREATED
	Suid := userdata.FileRecord[filename]
	Suuid := Suid[0:32]
	Skey := Suid[32:48]
	SHashkey := Suid[48:64]

	// FETCH SHARING RECORD FROM DATA STORE
	encryptRecord, e1 := userlib.DatastoreGet(string(Suuid))
	if e1 != true {
		return errors.New("FAILURE:: APPENDFILE --- DATASTOREGET")
	}
	// UNMARSHALL ENCRYPTED SHARING RECORD
	var cypertext []byte
	json.Unmarshal(encryptRecord, &cypertext)

	lenCyper := len(cypertext)
	AppendedMAC := cypertext[lenCyper-32:]
	AppendedIV := cypertext[:userlib.BlockSize]

	macValue := ComputeHashValue(cypertext[:lenCyper-32], SHashkey)

	if !userlib.Equal(AppendedMAC, macValue) {
		//fmt.Pri
		//ntln("not equal")
		return errors.New("INTEGRITY NOT PRESERVED")
	}

	//fmt.Println("Equal")
	//DecryptData(data []byte, key []byte, iv []byte)
	cipher := userlib.CFBDecrypter(Skey, AppendedIV)
	cipher.XORKeyStream(cypertext[userlib.BlockSize:lenCyper-32], cypertext[userlib.BlockSize:lenCyper-32])

	var shareRecord sharingRecord
	json.Unmarshal(cypertext[userlib.BlockSize:lenCyper-32], &shareRecord)

	//SHARING RECORD IS STORED IN shareRecord named variable

	//NOW WE APPEND ONE BLOCK AT A TIME AND STORE ITS INFORMATION INTO SHARING RECORD SIMULTANEOUSLY

	//GET NO. OF BLOCKS TO APPEND
	iterate := len(data) / configBlockSize
	startIndex := 0
	endIndex := configBlockSize
	// ITERATING FOR EACH BLOCK DATA
	for i := 0; i < iterate; i++ {
		//fmt.Println(i)
		// Creating Memory for BlockData and Storing
		BlockData := make([]byte, configBlockSize)
		BlockData = data[startIndex:endIndex]
		startIndex = endIndex
		endIndex = endIndex + configBlockSize

		// Creating buid,key and hashKey for each Block
		uid := userlib.RandomBytes(64)
		buid := uid[0:32]
		key := uid[32:48]
		hashKey := uid[48:64]

		// Storing Blockuuid in Sharing Record
		shareRecord.Blockuuid = append(shareRecord.Blockuuid, uid)
		shareRecord.Offset++

		// Encrypting the data
		ciphertext := EncryptData(BlockData, key)

		// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
		macd := ComputeHashValue(ciphertext, hashKey)

		// APPENDED CIPHERTEXT WITH MACVALUE
		Data := append(ciphertext, macd...)

		// Marshalling the data and then storing it in datastore
		marshalledData, e2 := json.Marshal(Data)
		if e2 != nil {
			return errors.New("FAILURE:: APPENDFILE --- MARSHALL DATA")
		}
		userlib.DatastoreSet(string(buid), marshalledData)
	}
	// FOR SHARING RECORD ENCRYPT + HASHVALUE + MARSHALL
	us, e3 := json.Marshal(shareRecord)
	if e3 != nil {
		return errors.New("FAILURE:: APPENDFILE --- MARSHALL DATA")
	}
	ciphertext := EncryptData(us, Skey)

	// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
	macd := ComputeHashValue(ciphertext, SHashkey)

	// APPENDED CIPHERTEXT WITH MACVALUE
	Data := append(ciphertext, macd...)

	// Marshalling the data and then storing it in datastore
	marshalledData, e4 := json.Marshal(Data)
	if e4 != nil {
		return errors.New("FAILURE:: APPENDFILE --- MARSHALL DATA")
	}
	userlib.DatastoreSet(string(Suuid), marshalledData)

	return nil
}

// LoadFile :This loads a block from a file in the Datastore.
//
// It should give an error if the file block is corrupted in any way.
// If there is no error, it must return exactly one block (of length blocksize)
// of data.
//
// LoadFile is also expected to be efficient. Reading a random block from the
// file should not fetch more than O(1) blocks from the Datastore.
func (userdata *User) LoadFile(filename string, offset int) (data []byte, err error) {

	// SHARING UID RECREATED
	if len(userdata.FileRecord[filename]) == 0 {
		return nil, errors.New("FAILURE:: LOADFILE:: FILENAME NOT FOUND")
	}
	Suid := userdata.FileRecord[filename]
	Suuid := Suid[0:32]
	Skey := Suid[32:48]
	SHashkey := Suid[48:64]

	// FETCH SHARING RECORD FROM DATA STORE
	encryptRecord, e1 := userlib.DatastoreGet(string(Suuid))
	if e1 != true {
		return nil, errors.New("FAILURE:: LOADFILE --- DATASTOREGET")
	}
	// UNMARSHALL ENCRYPTED SHARING RECORD
	var cypertext []byte
	json.Unmarshal(encryptRecord, &cypertext)

	lenCyper := len(cypertext)
	AppendedMAC := cypertext[lenCyper-32:]
	AppendedIV := cypertext[:userlib.BlockSize]

	macValue := ComputeHashValue(cypertext[:lenCyper-32], SHashkey)

	if !userlib.Equal(AppendedMAC, macValue) {
		//fmt.Pri
		//ntln("not equal")
		return nil, errors.New("FAILURE:: LOADFILE --- INTEGRITY NOT PRESERVED")
	}

	//fmt.Println("Equal")
	//DecryptData(data []byte, key []byte, iv []byte)
	cipher := userlib.CFBDecrypter(Skey, AppendedIV)
	cipher.XORKeyStream(cypertext[userlib.BlockSize:lenCyper-32], cypertext[userlib.BlockSize:lenCyper-32])

	var shareRecord sharingRecord
	json.Unmarshal(cypertext[userlib.BlockSize:lenCyper-32], &shareRecord)

	// offset exceeded
	if offset > shareRecord.Offset {
		return nil, errors.New("FAILURE:: LOADFILE:: OFFSET VALUE EXCEEDED")
	}

	// Accessing BlockDATA FROM DATASTORE
	uid := shareRecord.Blockuuid[offset-1] // 64byte uid
	suid := uid[0:32]
	BencryptRecord, e2 := userlib.DatastoreGet(string(suid))
	if e2 != true {
		return nil, errors.New("FAILURE:: LOADFILE --- DATASTOREGET")
	}
	var Bcypertext []byte
	json.Unmarshal(BencryptRecord, &Bcypertext)

	BlenCyper := len(Bcypertext)
	BAppendedMAC := Bcypertext[BlenCyper-32:]
	BAppendedIV := Bcypertext[:userlib.BlockSize]

	BmacValue := ComputeHashValue(Bcypertext[:BlenCyper-32], uid[48:64])

	if !userlib.Equal(BAppendedMAC, BmacValue) {
		//fmt.Println("not equal")
		return nil, errors.New("FAILURE:: LOADFILE --- INTEGRITY NOT PRESERVED")
	}

	//fmt.Println("Equal")
	//DecryptData(data []byte, key []byte, iv []byte)
	Bcipher := userlib.CFBDecrypter(uid[32:48], BAppendedIV)
	Bcipher.XORKeyStream(Bcypertext[userlib.BlockSize:BlenCyper-32], Bcypertext[userlib.BlockSize:BlenCyper-32])

	Data := Bcypertext[userlib.BlockSize : BlenCyper-32]

	return Data, nil
}

// ShareFile : Function used to the share file with other user
func (userdata *User) ShareFile(filename string, recipient string) (msgid string, err error) {
	//fmt.Println("-------------------in STORE FILE--------------------")
	if len(userdata.FileRecord[filename]) == 0 {
		return "", errors.New("FAILURE:: SHAREFILE:: FILENAME NOT FOUND")
	}
	data := userdata.FileRecord[filename]
	recvPubKey, e1 := userlib.KeystoreGet(recipient)
	if e1 != true {
		return "", errors.New("Failure:: SHAREFILE -- KEYSTOREGET")
	}
	//fmt.Println(recvPubKey)
	tag := []byte{0}
	encryptData, e2 := userlib.RSAEncrypt(&recvPubKey, data, tag)
	if e2 != nil {
		//fmt.Println("err1")
		return "", errors.New("Failure:: SHAREFILE -- RSAENCRYPT")
	}

	// SIGN IS 256 BYTES
	Sign, e3 := userlib.RSASign(userdata.PrivateKey, encryptData)
	if e3 != nil {
		//fmt.Println("err2")
		return "", errors.New("Failure:: SHAREFILE -- RSASIGN")
	}
	FData := append(encryptData, Sign...)
	//fmt.Println("LEN OF SIGN", len(Sign))
	//fmt.Println("LEN OF DATA", len(FData))

	return string(FData), nil
}

// ReceiveFile:Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
// ReceiveFile : function used to receive the file details from the sender

func (userdata *User) ReceiveFile(filename string, sender string, msgid string) error {
	//fmt.Println("-------------------in Receive FILE--------------------")

	sendPubKey, e1 := userlib.KeystoreGet(sender)
	if e1 != true {
		return errors.New("Failure:: Receive file --KeyStoreGet")
	}
	Data := []byte(msgid)
	lenData := len(Data)
	msg := Data[:lenData-256]
	sign := Data[lenData-256:]
	e2 := userlib.RSAVerify(&sendPubKey, msg, sign)
	//fmt.Println("LEN OF SIGN", len(sign))
	//fmt.Println("LEN OF DATA", len(msg))

	if e2 != nil {
		return errors.New("Failure:: Receive file --RSAVerify")
	}

	tag := []byte{0}
	actualMsg, e3 := userlib.RSADecrypt(userdata.PrivateKey, msg, tag)
	if e3 != nil {
		return errors.New("Failure:: Receive file --RSADecrypt")
	}

	userdata.FileRecord[filename] = actualMsg
	return nil
}

// RevokeFile : function used revoke the shared file access
func (userdata *User) RevokeFile(filename string) (err error) {

	if len(userdata.FileRecord[filename]) == 0 {
		return errors.New("FAILURE:: REVOKEFILE:: FILENAME NOT FOUND")
	}
	// ACCESSING OLD SHARING RECORD FROM USER STRUCTURE
	uid := userdata.FileRecord[filename]
	uuid := uid[0:32]
	key := uid[32:48]
	Hashkey := uid[48:64]

	// LOADING SHARING RECORD FROM DATA STORE
	shareR, e1 := userlib.DatastoreGet(string(uuid))
	if e1 != true {
		return errors.New("FAILURE:: Can't retrieve from data store")
	}
	// CHECKING INTEGRITY(MACVALUE) + DECRYPTION/ENCRYPTION AND FINAL RESULT IS SHARING RECORD STRUCTURE
	var cypertext []byte
	json.Unmarshal(shareR, &cypertext)
	//fmt.Println("Cypertext ::", cypertext)
	//unmarshalledData := cypertext.String()
	//sliceCyper := []byte(unmarshalledData)
	lenCyper := len(cypertext)
	//fmt.Println("length of cyper", lenCyper)
	AppendedMAC := cypertext[lenCyper-32:]
	AppendedIV := cypertext[:userlib.BlockSize]
	//fmt.Println("MAC DATA:: ", AppendedMAC)

	// Check AppendedMAC with ComputedMAC
	macValue := ComputeHashValue(cypertext[:lenCyper-32], Hashkey)
	/*computedMAC := userlib.NewHMAC(Hashkey)
	computedMAC.Write(cypertext[:lenCyper-32])
	macValue := computedMAC.Sum(nil)
	*/
	if !userlib.Equal(AppendedMAC, macValue) {
		//fmt.Println("not equal")
		return errors.New("INTEGRITY NOT PRESERVED")
	}
	//fmt.Println("Equal")

	//Decryption Happens here after successful MAC checking
	//fmt.Println("cypertext[userlib.BlockSize:lenCyper-32]:: ", cypertext[userlib.BlockSize:lenCyper-32])
	//cypertext[userlib.BlockSize : lenCyper-32] = DecryptData(cypertext[userlib.BlockSize:lenCyper-32], key, AppendedIV)

	//DecryptData(data []byte, key []byte, iv []byte)
	cipher := userlib.CFBDecrypter(key, AppendedIV)
	cipher.XORKeyStream(cypertext[userlib.BlockSize:lenCyper-32], cypertext[userlib.BlockSize:lenCyper-32])

	//fmt.Println("after decryption :: cypertext[userlib.BlockSize:lenCyper-32]:: ", cypertext[userlib.BlockSize:lenCyper-32])
	var share sharingRecord
	json.Unmarshal(cypertext[userlib.BlockSize:lenCyper-32], &share)

	// CREATING A SHARING RECORD AND CREATE ITS UID
	var shareRecord sharingRecord
	shareRecord.Offset = 0
	Suid := userlib.RandomBytes(64)
	Suuid := Suid[0:32]
	Skey := Suid[32:48]
	SHashkey := Suid[48:64]

	var i int
	iterate := share.Offset
	for i = 0; i < iterate; i++ {

		// LOADING COPY DATA + Creating Memory for BlockData and Storing
		data, e2 := userdata.LoadFile(filename, i+1)
		if e2 != nil {
			return errors.New("REVOKE FILE ::Error in LoadFILE ")
		}
		BlockData := make([]byte, configBlockSize)
		BlockData = data

		// Creating buid,key and hashKey for each Block
		uid := userlib.RandomBytes(64)
		buid := uid[0:32]
		key := uid[32:48]
		hashKey := uid[48:64]

		// Storing Blockuuid in Sharing Record
		shareRecord.Blockuuid = append(shareRecord.Blockuuid, uid)
		shareRecord.Offset++

		// Encrypting the data
		ciphertext := EncryptData(BlockData, key)

		// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
		macd := ComputeHashValue(ciphertext, hashKey)

		// APPENDED CIPHERTEXT WITH MACVALUE
		Data := append(ciphertext, macd...)

		// Marshalling the data and then storing it in datastore
		marshalledData, e3 := json.Marshal(Data)
		if e3 != nil {
			return errors.New("Failure:: JSON Object not created")
		}
		userlib.DatastoreSet(string(buid), marshalledData)
	}

	// FOR SHARING RECORD ENCRYPT + HASHVALUE + MARSHALL
	us, e4 := json.Marshal(shareRecord)
	if e4 != nil {
		return errors.New("Failure:: JSON Object not created")
	}
	ciphertext := EncryptData(us, Skey)

	// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
	macd := ComputeHashValue(ciphertext, SHashkey)

	// APPENDED CIPHERTEXT WITH MACVALUE
	Data := append(ciphertext, macd...)

	// Marshalling the data and then storing it in datastore
	marshalledData, e5 := json.Marshal(Data)
	if e5 != nil {
		return errors.New("Failure:: JSON Object not created")
	}
	userlib.DatastoreSet(string(Suuid), marshalledData)

	userdata.FileRecord[filename] = Suid
	return nil
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.
// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Offset    int
	Blockuuid [][]byte
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.
// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password

//InitUser : function used to create user
func InitUser(username string, password string) (userdataptr *User, err error) {
	//fmt.Println("-------------IN INIT USER-------------------")
	// Create uuid,key and HashKey using Argon2Key
	_, ok := userlib.KeystoreGet(username)
	if ok == true {
		return nil, errors.New("FAILURE:: INITUSER:: USERREADY EXIST")
	}
	uid := userlib.Argon2Key([]byte(password), []byte(username), 64)
	uuid := uid[0:32]
	key := uid[32:48]
	Hashkey := uid[48:64]

	// Generate RSA Key Pair
	var privkey *userlib.PrivateKey
	privkey, e1 := userlib.GenerateRSAKey()

	if e1 != nil {
		return nil, errors.New("RSA Keys not generated successfully")
	}
	//var pubKey *userlib.PrivateKey.PublicKey
	pubKey := privkey.PublicKey

	// Store Public Key in Keystore
	//fmt.Println(username, "---------", pubKey)
	userlib.KeystoreSet(username, pubKey)

	// Initialising User Structure
	var userStruct User
	userStruct.Username = username
	userStruct.Uuid = uuid
	userStruct.Key = key
	userStruct.PrivateKey = privkey
	userStruct.HashKey = Hashkey
	userStruct.FileRecord = make(map[string][]byte)

	// Encryption the Data
	// Marshal the encrypted data and then store in Data Store
	us, e2 := json.Marshal(userStruct)
	if e2 != nil {
		return nil, errors.New("JSON Object not created successfully")
	}
	//fmt.Println("-----us------", us)
	ciphertext := EncryptData(us, key)

	/*strUs := string(us)
	ciphertext := make([]byte, userlib.BlockSize+len(strUs))
	iv := ciphertext[:userlib.BlockSize]
	// Load random data
	copy(iv, userlib.RandomBytes(userlib.BlockSize))
	cipher := userlib.CFBEncrypter(key, iv)
	cipher.XORKeyStream(ciphertext[userlib.BlockSize:], []byte(strUs))
	*/
	//fmt.Println("ciphertext[userlib.BlockSize:]:::", ciphertext[userlib.BlockSize:])
	// Calculating HMAC value + Appending Cypertext(IV + Data) with HMAC value
	//var b bytes.Buffer
	//fmt.Println("LEN OF CYPER TEXT", len(ciphertext))
	//yt := reflect.TypeOf(ciphertext).Kind()
	//fmt.Println("type of ciphertext", yt)
	//b.WriteString(string(ciphertext))
	macd := ComputeHashValue(ciphertext, Hashkey)
	/*mac := userlib.NewHMAC(Hashkey)
	mac.Write(ciphertext)
	macd := mac.Sum(nil)
	*/
	//fmt.Println(string(macd))
	//fmt.Println("len of mac", len(macd))
	//xt := reflect.TypeOf(macd).Kind()
	//fmt.Println("type of mac", xt)
	Data := append(ciphertext, macd...)
	//fmt.Println("len of data:", len(Data))
	//fmt.Println("Data:", Data)
	//fmt.Println("mac Data:", macd)

	//b.WriteString(string(macd))
	marshalledData, e3 := json.Marshal(Data)
	if e3 != nil {
		return nil, errors.New("JSON Object not created successfully")
	}
	//fmt.Println("len of marshalled data", len(marshalledData))
	//fmt.Println("marshalled data", marshalledData)

	userlib.DatastoreSet(string(uuid), marshalledData)
	//fmt.Println("-----------OUT FROM INIT USER-----------------")

	return &userStruct, nil
}

// GetUser : This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
//GetUser : function used to get the user details
func GetUser(username string, password string) (userdataptr *User, err error) {
	//fmt.Println("-----------IN GetUSER-----------------")
	// Computing uid From Argon2Key
	uid := userlib.Argon2Key([]byte(password), []byte(username), 64)
	uuid := uid[0:32]
	key := uid[32:48]
	Hashkey := uid[48:64]

	// Get Data from DataStore
	data, e1 := userlib.DatastoreGet(string(uuid))
	if e1 != true {
		return nil, errors.New("Failure :: cannot retrieve from Data store")
	}
	//var g uuid.UUID
	//var cypertext bytes.Buffer
	var cypertext []byte
	json.Unmarshal(data, &cypertext)
	//fmt.Println("Cypertext ::", cypertext)
	//unmarshalledData := cypertext.String()
	//sliceCyper := []byte(unmarshalledData)
	lenCyper := len(cypertext)
	//fmt.Println("length of cyper", lenCyper)
	AppendedMAC := cypertext[lenCyper-32:]
	AppendedIV := cypertext[:userlib.BlockSize]
	//fmt.Println("MAC DATA:: ", AppendedMAC)

	// Check AppendedMAC with ComputedMAC
	macValue := ComputeHashValue(cypertext[:lenCyper-32], Hashkey)
	/*computedMAC := userlib.NewHMAC(Hashkey)
	computedMAC.Write(cypertext[:lenCyper-32])
	macValue := computedMAC.Sum(nil)
	*/
	if !userlib.Equal(AppendedMAC, macValue) {
		//fmt.Println("not equal")
		return nil, errors.New("INTEGRITY NOT PRESERVED")
	}
	//fmt.Println("Equal")

	//Decryption Happens here after successful MAC checking
	//fmt.Println("cypertext[userlib.BlockSize:lenCyper-32]:: ", cypertext[userlib.BlockSize:lenCyper-32])
	//cypertext[userlib.BlockSize : lenCyper-32] = DecryptData(cypertext[userlib.BlockSize:lenCyper-32], key, AppendedIV)

	//DecryptData(data []byte, key []byte, iv []byte)
	cipher := userlib.CFBDecrypter(key, AppendedIV)
	cipher.XORKeyStream(cypertext[userlib.BlockSize:lenCyper-32], cypertext[userlib.BlockSize:lenCyper-32])

	//fmt.Println("after decryption :: cypertext[userlib.BlockSize:lenCyper-32]:: ", cypertext[userlib.BlockSize:lenCyper-32])
	var userStruct User
	json.Unmarshal(cypertext[userlib.BlockSize:lenCyper-32], &userStruct)
	//fmt.Println(userStruct)
	//fmt.Println("-----------Out FROM GetUSER-----------------")

	return &userStruct, nil

}

func main() {
	c, _ := InitUser("cdhaddha", "chayan123")

	//userlib.DatastoreGet()
	a, _ := InitUser("anuraag", "anuraag123")

	s, _ := InitUser("shubham", "shubham123")
	   

	   data := userlib.RandomBytes(4096)
	   _ = c.StoreFile("file1", data)
	   //d, _ := c.LoadFile("file1", 1)
	   msgid, err1 := c. ShareFile("file1","anuraag")
	   if err1 != nil {
		   fmt.Println(err1)
	   }
	   err2 :=a.ReceiveFile("file2","chayan",msgid)
	   if err1 != nil {
			fmt.Println(err1)
	   }	
	   //TEST FOR APPEND DATA
	   //data2 := userlib.RandomBytes(4096)
	   //_ = c.StoreFile("file2", data2)
	   /*Appdata := userlib.RandomBytes(8192)
	   _ = c.AppendFile("file1", Appdata)
	   data1, _ := c.LoadFile("file1", 1)
	   data2, _ := c.LoadFile("file1", 2)
	   data3, _ := c.LoadFile("file1", 3)

	   if bytes.Compare(data[0:4096], data1) == 0 {
	   	fmt.Println("1st block EQUAL")
	   	//fmt.Println(blockdata)
	   }
	   if bytes.Compare(Appdata[0:4096], data2) == 0 {
	   	fmt.Println("2 block EQUAL")
	   	//fmt.Println(blockdata)
	   }
	   if bytes.Compare(Appdata[4096:8192], data3) == 0 {
	   	fmt.Println("3 block EQUAL")
	   	//fmt.Println(blockdata)
	   }
	   data4, e4 := c.LoadFile("file2", 1)
	   if e4 != nil {
	   	fmt.Println("e4 error file 2", data4)
	   }
	   data5, e5 := c.LoadFile("file1", 4)
	   if e5 != nil {
	   	fmt.Println("e5 error file 2", data5)
	   }
	   e6 := c.AppendFile("file2", Appdata)
	   if e6 != nil {
	   	fmt.Println("e6 error file 2")
	   }
	   //fmt.Println("---------APPENDED FILE AND THEN LOAD--------", blockdata2)
	   msgid, err := c.ShareFile("file1", "anuraag")
	   if err != nil {
	   	fmt.Println("ERROR IN SHARE FILE")
	   }
	   fmt.Println("msgid-----", msgid)
	   err2 := z.ReceiveFile("file2", "cdhaddha", msgid)

	   if err2 != nil {
	   	//fmt.Println(blockdata2)
	   }
	   //fmt.Println("SUCCESSFUL SHARE AND RECEIVE")
	   //fmt.Println(c.FileRecord["file2"])
	   err3 := c.RevokeFile("file2")
	   if err3 != nil {
	   	//fmt.Println(err2)
	   	//fmt.Println(d)
	   }
	   //fmt.Println("SUCCESSFUL REVOKE")

	   //fmt.Println(c.FileRecord["file2"])
	
}

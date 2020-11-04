package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	"github.com/benjaminwyss/pythia"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/sendgrid/sendgrid-go"
	"github.com/sendgrid/sendgrid-go/helpers/mail"
	"golang.org/x/crypto/bn256"
)

var QUERY_LIMIT int = 100

type SmartContract struct {
	contractapi.Contract
}

type ResultWithProof struct {
	Result string `json:"result"`
	P      string `json:"p"`
	C      string `json:"c"`
	U      string `json:"u"`
}

type UpdateTokenPackage struct {
	UpdateToken string `json:"updateToken"`
	PPrime      string `json:"pPrime"`
}

type QueryNote struct {
	Count     int       `json:"count"`
	Timestamp time.Time `json:"timestamp"`
}

func (s *SmartContract) Init(ctx contractapi.TransactionContextInterface) error {
	mskCheck, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if mskCheck != nil {
		return fmt.Errorf("Error. msk has already been initialized.")
	}

	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	mskBytes, ok := transMap["msk"]

	if !ok {
		return fmt.Errorf("msk not set in transient input.")
	}

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", "msk", mskBytes)

	if err != nil {
		return fmt.Errorf("Failed to put to private state. %s", err.Error())
	}
	return nil
}

func (s *SmartContract) InitSendGrid(ctx contractapi.TransactionContextInterface) error {
	sendgridCheck, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "sendgrid")

	if sendgridCheck != nil {
		return fmt.Errorf("Error. sendgrid key has already been initialized.")
	}

	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	sendgridBytes, ok := transMap["sendgrid"]

	if !ok {
		return fmt.Errorf("sendgrid key not set in transient input.")
	}

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", "sendgrid", sendgridBytes)

	if err != nil {
		return fmt.Errorf("Failed to put to private state. %s", err.Error())
	}
	return nil
}

func (s *SmartContract) Query(ctx contractapi.TransactionContextInterface, salt string, blindedHash string) (string, error) {
	mskBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if err != nil {
		return "", fmt.Errorf("Failed to get msk from private data store: %s", err.Error())
	}

	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return "", fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return "", fmt.Errorf("identity not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	prekeyBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if err != nil {
		return "", fmt.Errorf("Failed to get prekey value from private data store: %s", err.Error())
	}

	prekeyString := hex.EncodeToString(prekeyBytes)

	w := identityString + prekeyString

	x, _ := hex.DecodeString(blindedHash)

	mskString := hex.EncodeToString(mskBytes)

	//Evaluate password onion

	gt := pythia.Eval(w, salt, x, mskString)
	blindedResult := gt.Marshal()

	blindedResultString := hex.EncodeToString(blindedResult)

	return blindedResultString, nil
}

func (s *SmartContract) QueryWithProof(ctx contractapi.TransactionContextInterface, salt string, blindedHash string) (*ResultWithProof, error) {
	mskBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if err != nil {
		return nil, fmt.Errorf("Failed to get msk from private data store: %s", err.Error())
	}

	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return nil, fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return nil, fmt.Errorf("identity not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	prekeyBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if err != nil {
		return nil, fmt.Errorf("Failed to get prekey from private data store: %s", err.Error())
	}

	prekeyString := hex.EncodeToString(prekeyBytes)

	w := identityString + prekeyString

	x, _ := hex.DecodeString(blindedHash)

	mskString := hex.EncodeToString(mskBytes)

	//Evaluate password onion

	gt := pythia.Eval(w, salt, x, mskString)
	blindedResult := gt.Marshal()

	blindedResultString := hex.EncodeToString(blindedResult)

	saltHash := sha256.Sum256([]byte(salt))
	blindHashBytes, _ := hex.DecodeString(blindedHash)

	p, c, u := pythia.GenerateProof(blindHashBytes, saltHash[:], pythia.GenKw(w, mskString), blindedResult)

	pString := hex.EncodeToString(p)
	cString := hex.EncodeToString(c.Bytes())
	uString := hex.EncodeToString(u.Bytes())

	resultWithProof := ResultWithProof{blindedResultString, pString, cString, uString}

	return &resultWithProof, nil
}

func (s *SmartContract) Register(ctx contractapi.TransactionContextInterface) (string, error) {
	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return "", fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return "", fmt.Errorf("identity not set in transient input.")
	}

	prekeyBytes, ok := transMap["prekey"]

	if !ok {
		return "", fmt.Errorf("prekey not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	identityCheck, _ := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if identityCheck != nil {
		return "", fmt.Errorf("Error. Identity has already been registered")
	}

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", identityString, prekeyBytes)

	if err != nil {
		return "", fmt.Errorf("Failed to put to private data store: %s", err.Error())
	}

	prekeyString := hex.EncodeToString(prekeyBytes)

	mskBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if err != nil {
		return "", fmt.Errorf("Failed to get msk from private data store: %s", err.Error())
	}

	mskString := hex.EncodeToString(mskBytes)

	kw := pythia.GenKw(identityString+prekeyString, mskString)
	kwInt := new(big.Int).SetBytes(kw)

	pQ := new(bn256.G1).ScalarBaseMult(kwInt)
	pBytes := pQ.Marshal()

	pString := hex.EncodeToString(pBytes)

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", "p", pBytes)

	if err != nil {
		return "", fmt.Errorf("Failed to write public key to private data store: %s", err.Error())
	}

	return pString, nil
}

func (s *SmartContract) RegisterEmail(ctx contractapi.TransactionContextInterface) error {
	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return fmt.Errorf("identity not set in transient input.")
	}

	emailBytes, ok := transMap["email"]

	if !ok {
		return fmt.Errorf("email not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	identityCheck, _ := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if identityCheck == nil {
		return fmt.Errorf("Error. Identity has not been registered")
	}

	emailCheck, _ := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString+"email")

	if emailCheck != nil {
		return fmt.Errorf("Error. Email has already been registered for your identity")
	}

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", identityString+"email", emailBytes)

	if err != nil {
		return fmt.Errorf("Error. Failed to put to private data store. %s", err.Error())
	}
	return nil
}

func (s *SmartContract) GenerateUpdateToken(ctx contractapi.TransactionContextInterface) (*UpdateTokenPackage, error) {
	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return nil, fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return nil, fmt.Errorf("identity not set in transient input.")
	}

	prekeyPrimeBytes, ok := transMap["prekey"]

	if !ok {
		return nil, fmt.Errorf("new prekey not set in transient input.")
	}

	authTokenBytes, ok := transMap["authToken"]

	if !ok {
		return nil, fmt.Errorf("authorization token not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	prekeyBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if err != nil {
		return nil, fmt.Errorf("Failed to get prekey from private data store: %s", err.Error())
	}

	if prekeyBytes == nil {
		return nil, fmt.Errorf("Error. Identity has not been registered")
	}

	mskBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if err != nil {
		return nil, fmt.Errorf("Failed to get msk from private data store: %s", err.Error())
	}

	mskString := hex.EncodeToString(mskBytes)

	authToken := hex.EncodeToString(authTokenBytes)

	prekeyString := hex.EncodeToString(prekeyBytes)
	prekeyPrimeString := hex.EncodeToString(prekeyPrimeBytes)

	w := identityString + prekeyString
	wPrime := identityString + prekeyPrimeString

	//Verify the authorization token matches

	kw := pythia.GenKw(w, mskString)
	kwInt := new(big.Int).SetBytes(kw)

	authQ := new(bn256.G2).ScalarBaseMult(kwInt)
	authBytes := authQ.Marshal()

	authTokenCorrect := hex.EncodeToString(authBytes)

	if authToken != authTokenCorrect {
		return nil, fmt.Errorf("Error. Input authorization token does not match correct authorization token.")
	}

	//Generate update token package

	token := pythia.GenUpdateToken(w, wPrime, mskString)
	tokenString := hex.EncodeToString(token.Bytes())

	kwPrime := pythia.GenKw(wPrime, mskString)
	kwPrimeInt := new(big.Int).SetBytes(kwPrime)

	pPrimeQ := new(bn256.G1).ScalarBaseMult(kwPrimeInt)
	pPrimeBytes := pPrimeQ.Marshal()

	pPrimeString := hex.EncodeToString(pPrimeBytes)

	updateTokenPackage := UpdateTokenPackage{tokenString, pPrimeString}

	//Update existing prekey value in private data store before returning

	err = ctx.GetStub().PutPrivateData("pythiaPrivate", identityString, prekeyPrimeBytes)

	if err != nil {
		return nil, fmt.Errorf("Failed to put to private data store: %s", err.Error())
	}

	return &updateTokenPackage, nil

}

func (s *SmartContract) GenerateAuthToken(ctx contractapi.TransactionContextInterface) (string, error) {
	sendgridCheck, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "sendgrid")

	if sendgridCheck == nil {
		return "", fmt.Errorf("Error. sendgrid key has not been initialized.")
	}

	transMap, err := ctx.GetStub().GetTransient()

	if err != nil {
		return "", fmt.Errorf("Failed to get transient input. %s", err.Error())
	}

	identityBytes, ok := transMap["identity"]

	if !ok {
		return "", fmt.Errorf("identity not set in transient input.")
	}

	identityString := hex.EncodeToString(identityBytes)

	prekeyBytes, _ := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString)

	if prekeyBytes == nil {
		return "", fmt.Errorf("Error. Identity is not registered")
	}

	emailCheck, _ := ctx.GetStub().GetPrivateData("pythiaPrivate", identityString+"email")

	if emailCheck == nil {
		return "", fmt.Errorf("Error. Identity does not have a registered email")
	}

	mskBytes, err := ctx.GetStub().GetPrivateData("pythiaPrivate", "msk")

	if err != nil {
		return "", fmt.Errorf("Failed to get msk from private data store: %s", err.Error())
	}

	mskString := hex.EncodeToString(mskBytes)

	prekeyString := hex.EncodeToString(prekeyBytes)

	//Generate Authorization Token

	kw := pythia.GenKw(identityString+prekeyString, mskString)
	kwInt := new(big.Int).SetBytes(kw)

	authQ := new(bn256.G2).ScalarBaseMult(kwInt)
	authBytes := authQ.Marshal()

	authToken := hex.EncodeToString(authBytes)

	//Send Email

	email := string(emailCheck)

	key := string(sendgridCheck)

	from := mail.NewEmail("Pythia Blockchain Do Not Reply", "pythiablockchain@gmail.com")
	subject := "Authorization Token"
	to := mail.NewEmail("Pythia User", email)
	plainTextContent := "Dear Pythia Blockchain User,\nYou are receiving this email because a request was made to generate the authorization token associated with this email address.\nYour authorization token is:\n" + authToken + "\nIf you did not make this request, please delete this email.\nSincerely,\nPythia Blockchain Team"
	htmlContent := "<p>Dear Pythia Blockchain User,</p><p>You are receiving this email because a request was made to generate the authorization token associated with this email address.</p><p>Your authorization token is:</p><p>" + authToken + "</p><p>If you did not make this request, please delete this email.</p><p>Sincerely,</p><p>Pythia Blockchain Team</p>"
	message := mail.NewSingleEmail(from, subject, to, plainTextContent, htmlContent)
	client := sendgrid.NewSendClient(key)
	response, err := client.Send(message)

	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d\n%s\n%s", response.StatusCode, response.Headers, response.Body), nil

}

func main() {
	chaincode, err := contractapi.NewChaincode(new(SmartContract))
	if err != nil {
		fmt.Printf("Error creating pythia chaincode: %s", err.Error())
		return
	}

	if err := chaincode.Start(); err != nil {
		fmt.Printf("Error starting pythia chaincode: %s", err.Error())
	}
}

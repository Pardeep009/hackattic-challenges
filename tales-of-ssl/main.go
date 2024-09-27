package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
)

const (
	problem_get_url  = "https://hackattic.com/challenges/tales_of_ssl/problem?access_token=<access-token>"
	problem_post_url = "https://hackattic.com/challenges/tales_of_ssl/solve?access_token=<access-token>"
)

type Details struct {
	Domain       string `json:"domain"`
	SerialNumber string `json:"serial_number"`
	Country      string `json:"country"`
}

type Problem struct {
	PrivateKey   string  `json:"private_key"`
	RequiredData Details `json:"required_data"`
}

func getProblem() (Problem, error) {

	resp, err := http.Get(problem_get_url)

	if err != nil {
		fmt.Println("Error while getting problem:", err)
		return Problem{}, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error while reading response body: ", err)
		return Problem{}, err
	}

	var problem Problem

	err = json.Unmarshal(body, &problem)
	if err != nil {
		fmt.Println("Error while parsing json: ", err)
		return Problem{}, err
	}

	return problem, nil
}

func createCertificate(problem Problem) (string, error) {
	// 1. Create a certificate template
	serialNo, err := strconv.ParseInt(problem.RequiredData.SerialNumber[2:], 16, 64)
	if err != nil {
		fmt.Println("Error while parsing serial no to int: ", err)
		return "", err
	}
	certTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(serialNo),
		Subject: pkix.Name{
			Country:    []string{"CI"},
			CommonName: problem.RequiredData.Domain,
		},
	}

	//2. Extract public key from given private key
	keyBytes, err := base64.StdEncoding.DecodeString(problem.PrivateKey)
	if err != nil {
		fmt.Println("Error decoding base64 key:", err)
		return "", err
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(keyBytes)
	if err != nil {
		fmt.Println("Failed to parse RSA private key:", err)
		return "", err
	}
	publicKey := privateKey.Public()

	//3. Self sign the certificate using private key
	certDER, err := x509.CreateCertificate(rand.Reader, certTemplate, certTemplate, publicKey, privateKey)
	if err != nil {
		fmt.Println("Error creating certificate:", err)
		return "", err
	}

	//4. Encode the DER format certificate to base64
	base64Cert := base64.StdEncoding.EncodeToString(certDER)
	return base64Cert, nil
}

func postSolution(base64Cert string) error {
	data := map[string]string{
		"certificate": base64Cert,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		fmt.Println("Error encoding JSON data:", err)
		return err
	}
	resp, err := http.Post(problem_post_url, "Content-Type: application/json", bytes.NewBuffer(jsonData))
	// req, err := http.NewRequest("POST", problem_post_url, bytes.NewBuffer(jsonData))
	// if err != nil {
	// 	fmt.Println("Error creating POST request", err)
	// 	return err
	// }
	// req.Header.Set("Content-Type", "application/json")
	// client := &http.Client{}
	// resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending POST request", err)
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response", err)
		return err
	}
	fmt.Println("Response:", string(body))
	return nil
}

func main() {
	var problem Problem
	problem, err := getProblem()
	if err != nil {
		fmt.Println("Error while getting problem:", err)
		return
	}
	base64Cert, err := createCertificate(problem)
	if err != nil {
		fmt.Println("Error while creating certificate:", err)
		return
	}
	err = postSolution(base64Cert)
	if err != nil {
		fmt.Println("Error while submitting response", err)
		return
	}
}

package main

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path"
)

func handleError(err error, msg string, fatal ...bool) bool {
	msg = msg + ":"
	if err != nil {
		if len(fatal) > 0 && fatal[0] == true {
			log.Fatalln(msg, err)
		}
		log.Println(msg, err)
		return true
	}
	return false
}

type KeyboardInteractivePassword string

func (pwd KeyboardInteractivePassword) keyboardInteractiveChallenge(user, instruction string, questions []string,
	echos []bool, ) (answers []string, err error) {

	if len(questions) == 0 {
		return []string{}, nil
	}
	return []string{string(pwd)}, nil
}

func publicKeyAuthFunc(kPath string) ssh.AuthMethod {
	keyPath, err := homedir.Expand(kPath)
	if handleError(err, "Expand") {
		return nil
	}
	info, err := os.Stat(keyPath)
	if info == nil || info.IsDir() {
		return nil
	}
	key, err := ioutil.ReadFile(keyPath)
	if handleError(err, "ReadFile") {
		return nil
	}
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if handleError(err, "ParsePrivateKey") {
		return nil
	}
	return ssh.PublicKeys(signer)
}

func GetAuthMethodAll(pwd, kPath string) []ssh.AuthMethod {
	return []ssh.AuthMethod{
		ssh.Password(pwd),
		ssh.KeyboardInteractive(KeyboardInteractivePassword(pwd).keyboardInteractiveChallenge),
		publicKeyAuthFunc(kPath),
	}
}

type ErrorHandleFunc func(path1, path2 string, err error)

func uploadFile(sftpClient *sftp.Client, localPath string, remotePath string) error {
	srcFile, err := os.Open(localPath)
	if handleError(err, "os.Open") {
		return err
	}
	defer func() {
		err = srcFile.Close()
		handleError(err, "srcFile.Close")
	}()
	info, err := sftpClient.Stat(remotePath)
	if info != nil && info.IsDir() {
		remotePath = path.Join(remotePath, srcFile.Name())
	}
	dstFile, err := sftpClient.Create(remotePath)
	if handleError(err, "sftpClient.Create") {
		return err
	}
	defer func() {
		err = dstFile.Close()
		handleError(err, "dstFile.Close")
	}()
	_, err = io.Copy(dstFile, srcFile)
	if handleError(err, "io.Copy") {
		return err
	}
	_ = sftpClient.Chmod(remotePath, os.ModePerm)
	return nil
}

func uploadDirectory(sftpClient *sftp.Client, localPath string, remotePath string, errHandleFunc ErrorHandleFunc) {
	localFileInfoList, err := ioutil.ReadDir(localPath)
	if handleError(err, "ReadDir") {
		errHandleFunc(localPath, remotePath, err)
		return
	}
	for _, t := range localFileInfoList {
		localFileInfo := t
		localFilePath := path.Join(localPath, localFileInfo.Name())
		remoteFilePath := path.Join(remotePath, localFileInfo.Name())
		if localFileInfo.IsDir() {
			err = sftpClient.MkdirAll(remoteFilePath)
			handleError(err, "MkdirAll")
			uploadDirectory(sftpClient, localFilePath, remoteFilePath, errHandleFunc)
		} else {
			err = uploadFile(sftpClient, localFilePath, remoteFilePath)
			if handleError(err, "uploadFile") {
				errHandleFunc(localFilePath, remoteFilePath, err)
				//t := append(**failedList, [2]string{localFilePath, remoteFilePath})
				//*failedList = &t
			}
		}
	}
}

func download(sftpClient *sftp.Client, remotePath, localPath string) error {
	remoteFile, err := sftpClient.Open(remotePath)
	if handleError(err, "sftpClient.Open") {
		return err
	}
	defer func() {
		err = remoteFile.Close()
		handleError(err, "remoteFile.Close")
	}()
	info, err := os.Stat(localPath)
	if info != nil && info.IsDir() {
		localPath = path.Join(localPath, remoteFile.Name())
	}
	localFile, err := os.Create(localPath)
	if handleError(err, "os.Create") {
		return err
	}
	defer func() {
		err = localFile.Close()
		handleError(err, "localFile.Close")
	}()
	_, err = io.Copy(localFile, remoteFile)
	if handleError(err, "io.Copy") {
		return err
	}
	_ = os.Chmod(localPath, os.ModePerm)
	return nil
}

func downloadDirectory(sftpClient *sftp.Client, remotePath string, localPath string, errHandleFunc ErrorHandleFunc) {
	remoteFileInfoList, err := sftpClient.ReadDir(localPath)
	if handleError(err, "sftpClient.ReadDir") {
		errHandleFunc(remotePath, localPath, err)
		return
	}
	for _, t := range remoteFileInfoList {
		remoteFileInfo := t
		remoteFilePath := path.Join(remotePath, remoteFileInfo.Name())
		localFilePath := path.Join(localPath, remoteFileInfo.Name())
		if remoteFileInfo.IsDir() {
			err = os.MkdirAll(localFilePath, os.ModePerm)
			handleError(err, "MkdirAll")
			downloadDirectory(sftpClient, remoteFilePath, localFilePath, errHandleFunc)
		} else {
			err = download(sftpClient, remoteFilePath, localFilePath)
			if handleError(err, "uploadFile") {
				errHandleFunc(remoteFilePath, localFilePath, err)
			}
		}
	}
}

func main() {
	host := "127.0.0.1"
	port := "2200"
	user := "alone"
	pwd := "123456"
	kPath := "~/.ssh"
	auth := GetAuthMethodAll(pwd, kPath)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port),
		&ssh.ClientConfig{
			User:            user,
			Auth:            auth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
	handleError(err, "Dial", true)
	session, err := client.NewSession()
	handleError(err, "new session", true)
	out, err := session.Output("echo aaa")
	fmt.Println(string(out))
	defer session.Close()
}

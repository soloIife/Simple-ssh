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

func HandleError(err error, msg string, fatal ...bool) bool {
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
	if HandleError(err, "Expand") {
		return nil
	}
	info, err := os.Stat(keyPath)
	if info == nil || info.IsDir() {
		return nil
	}
	key, err := ioutil.ReadFile(keyPath)
	if HandleError(err, "ReadFile") {
		return nil
	}
	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if HandleError(err, "ParsePrivateKey") {
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

type SshKit struct {
	sshClient  *ssh.Client
	sftpClient *sftp.Client
}

func (kit *SshKit) Close() error {
	return kit.sshClient.Close()
}

func (kit *SshKit) Upload(localPath string, remotePath string) error {
	srcFile, err := os.Open(localPath)
	if HandleError(err, "os.Open") {
		return err
	}
	defer func() {
		err = srcFile.Close()
		HandleError(err, "srcFile.Close")
	}()
	info, err := kit.sftpClient.Stat(remotePath)
	_, localName := path.Split(localPath)
	if info == nil {
		remoteDir, _ := path.Split(remotePath)
		_ = kit.sftpClient.MkdirAll(remoteDir)
		if remotePath[len(remotePath)-1] == '/' {
			remotePath = path.Join(remotePath, localName)
		}
	} else if info.IsDir() {
		remotePath = path.Join(remotePath, localName)
	}
	dstFile, err := kit.sftpClient.Create(remotePath)
	if HandleError(err, "sftpClient.Create") {
		return err
	}
	defer func() {
		err = dstFile.Close()
		HandleError(err, "dstFile.Close")
	}()
	_, err = io.Copy(dstFile, srcFile)
	if HandleError(err, "io.Copy") {
		return err
	}
	_ = kit.sftpClient.Chmod(remotePath, os.ModePerm)
	return nil
}

func (kit *SshKit) UploadDir(localPath string, remotePath string, errHandleFunc ErrorHandleFunc) {
	localFileInfoList, err := ioutil.ReadDir(localPath)
	if HandleError(err, "ReadDir") {
		errHandleFunc(localPath, remotePath, err)
		return
	}
	for _, t := range localFileInfoList {
		localFileInfo := t
		localFilePath := path.Join(localPath, localFileInfo.Name())
		remoteFilePath := path.Join(remotePath, localFileInfo.Name())
		if localFileInfo.IsDir() {
			err = kit.sftpClient.MkdirAll(remoteFilePath)
			HandleError(err, "MkdirAll")
			kit.UploadDir(localFilePath, remoteFilePath, errHandleFunc)
		} else {
			err = kit.Upload(localFilePath, remoteFilePath)
			if HandleError(err, "Upload") {
				errHandleFunc(localFilePath, remoteFilePath, err)
				//t := append(**failedList, [2]string{localFilePath, remoteFilePath})
				//*failedList = &t
			}
		}
	}
}

func (kit *SshKit) Download(remotePath, localPath string) error {
	remoteFile, err := kit.sftpClient.Open(remotePath)
	if HandleError(err, "sftpClient.Open") {
		return err
	}
	defer func() {
		err = remoteFile.Close()
		HandleError(err, "remoteFile.Close")
	}()
	info, err := os.Stat(localPath)
	_, remoteName := path.Split(remotePath)
	if info == nil {
		localDir, _ := path.Split(localPath)
		err = os.MkdirAll(localDir, os.ModePerm)
		if localPath[len(localPath)-1] == '/' {
			localPath = path.Join(localPath, remoteName)
		}
	} else if info.IsDir() {
		localPath = path.Join(localPath, remoteName)
	}
	localFile, err := os.Create(localPath)
	if HandleError(err, "os.Create") {
		return err
	}
	defer func() {
		err = localFile.Close()
		HandleError(err, "localFile.Close")
	}()
	_, err = io.Copy(localFile, remoteFile)
	if HandleError(err, "io.Copy") {
		return err
	}
	_ = os.Chmod(localPath, os.ModePerm)
	return nil
}

func (kit *SshKit) DownloadDir(remotePath string, localPath string, errHandleFunc ErrorHandleFunc) {
	remoteFileInfoList, err := kit.sftpClient.ReadDir(remotePath)
	if HandleError(err, "sftpClient.ReadDir") {
		errHandleFunc(remotePath, localPath, err)
		return
	}
	for _, t := range remoteFileInfoList {
		remoteFileInfo := t
		remoteFilePath := path.Join(remotePath, remoteFileInfo.Name())
		localFilePath := path.Join(localPath, remoteFileInfo.Name())
		if remoteFileInfo.IsDir() {
			err = os.MkdirAll(localFilePath, os.ModePerm)
			HandleError(err, "MkdirAll")
			kit.DownloadDir(remoteFilePath, localFilePath, errHandleFunc)
		} else {
			err = kit.Download(remoteFilePath, localFilePath)
			if HandleError(err, "Download") {
				errHandleFunc(remoteFilePath, localFilePath, err)
			}
		}
	}
}

func main() {
	host := "127.0.0.1"
	port := "2200"
	user := "root"
	pwd := "123456"
	kPath := "~/.ssh"
	auth := GetAuthMethodAll(pwd, kPath)
	sshClient, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", host, port),
		&ssh.ClientConfig{
			User:            user,
			Auth:            auth,
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		})
	HandleError(err, "Dial", true)
	session, err := sshClient.NewSession()
	HandleError(err, "new session", true)
	out, err := session.Output("echo aaa")
	fmt.Println(string(out))
	defer session.Close()
	sftpClient, err := sftp.NewClient(sshClient)
	sshKit := SshKit{
		sshClient:  sshClient,
		sftpClient: sftpClient,
	}
	_ = sshKit.Download("/tmp/a.txt", "d:/")
	sshKit.DownloadDir("/root/", "e:/root", func(path1, path2 string, err error) {
		fmt.Println("Download error:", path1, path2, err)
	})
}

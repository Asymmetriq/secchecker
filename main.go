package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/archive"
)

const dockerfile = `
FROM golang:latest

WORKDIR /app
ENV GO111MODULE=on

COPY . ./
RUN go mod download

RUN go install github.com/securego/gosec/v2/cmd/gosec@latest
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
RUN go get github.com/stripe/safesql

CMD gosec ./... && govulncheck ./... && safesql ./...`

func main() {
	ctx := context.Background()
	pathFlag := flag.String("path", ".", "path to the directory containing the go files")
	flag.Parse()
	if pathFlag == nil {
		log.Fatal("path flag is nil")
	}

	err := os.WriteFile(*pathFlag+"/Dockerfile", []byte(dockerfile), 0777)
	if err != nil {
		fmt.Printf("Unable to write file: %v", err)
	}

	cli, err := client.NewClientWithOpts()
	if err != nil {
		log.Fatal(err, " :unable to init client")
	}

	files, err := WalkMatch(*pathFlag, "*.go")
	if err != nil {
		log.Fatal(err, " :unable to walk files")
	}

	reader, err := archive.TarWithOptions(*pathFlag, &archive.TarOptions{
		IncludeFiles: append(files, []string{"go.mod", "go.sum", "Dockerfile"}...),
	})
	if err != nil {
		log.Fatal(err, " :unable to create tar")
	}

	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		reader,
		types.ImageBuildOptions{
			Tags:       []string{"secchecker"},
			Context:    reader,
			Dockerfile: "Dockerfile",
			PullParent: true,
			Labels:     map[string]string{"custom": "test"},
		})
	if err != nil {
		log.Fatal(err, " :unable to build docker image")
	}
	defer imageBuildResponse.Body.Close()
	_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	if err != nil {
		log.Fatal(err, " :unable to read image build response")
	}
}

func WalkMatch(root, pattern string) ([]string, error) {
	var matches []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(pattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			r, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			matches = append(matches, r)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return matches, nil
}

FROM golang:1.10

ADD . /go/src/github.com/stephen-soltesz/gosh
RUN go get -v github.com/stephen-soltesz/gosh/cmd/gosh

CMD ["bash"]
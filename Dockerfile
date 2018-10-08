FROM golang:1.10

#ADD . /go/src/github.com/stephen-soltesz/gosh
#RUN go get -v github.com/stephen-soltesz/gosh/cmd/gosh
RUN apt-get update && apt-get install -y vim

CMD ["bash"]

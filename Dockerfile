FROM golang as build

WORKDIR /go/src/app
COPY . .

RUN go get -d -v ./...
RUN go install -v ./...


FROM scratch
COPY --from=build /go/bin/drcmpesaproxy /bin/drcmpesaproxy
ENV PORT 8080
EXPOSE 8080
CMD ["drcmpesaproxy"]

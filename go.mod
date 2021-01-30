module github.com/jetstack/cert-manager-webhook-lego

go 1.13

require (
	github.com/go-acme/lego/v4 v4.2.0
	github.com/jetstack/cert-manager v1.1.0
	gonum.org/v1/netlib v0.0.0-20190331212654-76723241ea4e // indirect
	k8s.io/api v0.19.0
	k8s.io/apiextensions-apiserver v0.19.0
	k8s.io/apimachinery v0.19.0
	k8s.io/client-go v0.19.0
	sigs.k8s.io/structured-merge-diff v1.0.1-0.20191108220359-b1b620dd3f06 // indirect
)

replace go.etcd.io/etcd/ => go.etcd.io/etcd/ v0.4.9

replace github.com/jetstack/cert-manager => ./cert-manager

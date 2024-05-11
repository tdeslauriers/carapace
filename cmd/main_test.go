package main

import "testing"

type Dog string

const (
	GoldenRetriever Dog = "Golden Retriever"
	Beagle          Dog = "Beagle"
	Chihuahua       Dog = "Chihuahua"
	Doberman        Dog = "Doberman Pinscher"
	Poodle          Dog = "Poodle"
	Pompom             Dog = "Pomeranian"
)

func TestTypeAlias(t *testing.T)  {
	
	baddie := Pompom
	t.Logf("Maddie is a %s", baddie)
}
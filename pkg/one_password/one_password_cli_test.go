package onepassword

import "testing"

func TestGetDoc(t *testing.T) {
	cli := NewCli()
	_, err := cli.GetDocument("world_shaw_client_cert_dev", "Shared")
	if err != nil {
		t.Errorf("error getting document: %v", err)
	}

}

func TestCreateDoc(t *testing.T) {
	cli := NewCli()

	if err := cli.CreateDocument("/home/atomic/workspace/certs/exo/test.txt", "monkey_wrenc", "Shared", []string{"Family Site"}); err != nil {

		t.Errorf("error creating document: %v", err)
	}

}

func TestEditDoc(t *testing.T) {
	cli := NewCli()

	if err := cli.EditDocument("/home/atomic/workspace/certs/exo/test.txt", "monkey_wrench"); err != nil {
		t.Errorf("error editing document: %v", err)
	}

}

func TestGetItem(t *testing.T) {
	cli := NewCli()
	item, err := cli.GetItem("monkey_wrench", "Shared")
	if err != nil {
		t.Errorf("error getting item: %v", err)
	}

	t.Logf("item: %+v", item)
}

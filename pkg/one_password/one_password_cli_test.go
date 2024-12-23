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

	if err := cli.CreateDocument("./exo/test.txt", "monkey_wrenc", "Shared", []string{"Family Site"}); err != nil {

		t.Errorf("error creating document: %v", err)
	}

}

func TestEditDoc(t *testing.T) {
	cli := NewCli()

	if err := cli.EditDocument("./exo/test.txt", "monkey_wrench"); err != nil {
		t.Errorf("error editing document: %v", err)
	}

}

func TestGetItem(t *testing.T) {
	cli := NewCli()
	item, err := cli.GetItem("monkey_wrench", "world_site")
	if err != nil {
		t.Errorf("error getting item: %v", err)
	}

	t.Logf("item: %+v", item)
}

func TestCreateItem(t *testing.T) {

	cli := NewCli()
	item := &Item{
		Title:    "monkey_wrench",
		Vault:    Vault{Name: "world_site"},
		Tags:     []string{"Family Site"},
		Category: "Login",
		Fields: []Field{
			{Label: "test_key", Value: "password123", Type: "concealed"},
		},
	}

	if err := cli.CreateItem(item); err != nil {
		t.Errorf("error creating item: %v", err)
	}
}

func TestEditItem(t *testing.T) {
	cli := NewCli()
	item, err := cli.GetItem("monkey_wrench", "world_site")
	if err != nil {
		t.Errorf("error getting item: %v", err)
	}

	for i, f := range item.Fields {
		if f.Label == "test_key" {
			item.Fields[i].Value = "totally_different_password"
			break
		}
	}

	if err := cli.EditItem(item); err != nil {
		t.Errorf("error editing item: %v", err)
	}
}

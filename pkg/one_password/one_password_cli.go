package onepassword

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/tdeslauriers/carapace/internal/util"
)

// Cli is an interface for the one_password cli.
type Cli interface {
	// GetDocument gets a document from 1password if it exists
	GetDocument(title, vault string) ([]byte, error)

	// CreateDocument creates a document item in 1password
	CreateDocument(file, title, vault string, tags []string) error

	// EditDocument edits a document in 1password
	EditDocument(file, title string) error

	// GetItem gets an item from 1password if it exists
	GetItem(title, vault string) (*Item, error)

	// CreateItem creates an item in 1password
	CreateItem(item *Item) error

	// EditItem edits an item in 1password
	EditItem(item *Item) error
}

// NewCli is a factory function that returns a new one_password cli interface.
func NewCli() Cli {
	return &cli{
		logger: slog.Default().With(slog.String(util.ComponentKey, util.ComponentOnePassword)),
	}
}

var _ Cli = (*cli)(nil)

// cli is the concrete implementation of the Cli interface.
type cli struct {
	logger *slog.Logger
}

// GetDocument gets a document from 1password if it exists
func (c *cli) GetDocument(title, vault string) ([]byte, error) {

	// prepare op command
	cmd := exec.Command("op", "document", "get", title, "--vault", vault)

	var out bytes.Buffer
	cmd.Stdout = &out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// run op command
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error running op get document %s: %v; stderr: %s", title, err, stderr.String())
	}

	return out.Bytes(), nil
}

func (c *cli) CreateDocument(file, title, vault string, tags []string) error {

	// prepare tags
	builder := strings.Builder{}
	counter := 0
	for _, tag := range tags {
		builder.WriteString(tag)
		if counter < len(tags)-1 {
			builder.WriteString(", ")
		}
		counter++
	}

	// prepar op command
	cmd := exec.Command(
		"op", "document", "create", file,
		"--title", title,
		"--vault", vault,
		"--tags", builder.String(),
	)

	var out bytes.Buffer
	cmd.Stdout = &out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// run op command
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error running op create document %s : %v; stderr: %s", title, err, stderr.String())
	}

	c.logger.Info(fmt.Sprintf("1password document created: %s", out.String()))

	return nil
}

// EditDocument edits a document in 1password
func (c *cli) EditDocument(file, title string) error {

	// prepare op command
	cmd := exec.Command(
		"op", "document", "edit", title, file)

	var out bytes.Buffer
	cmd.Stdout = &out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// run op command
	err := cmd.Run()
	if err != nil {
		return fmt.Errorf("error running `op edit document %s %s`: %v; stderr: %s", title, file, err, stderr.String())
	}

	c.logger.Info(fmt.Sprintf("1password document edited %s successfully: %s", title, out.String()))

	return nil
}

// GetItem gets an item from 1password if it exists
func (c *cli) GetItem(title, vault string) (*Item, error) {

	// prepare op command
	cmd := exec.Command("op", "item", "get", title, "--vault", vault, "--format", "json", "--reveal")

	var out bytes.Buffer
	cmd.Stdout = &out

	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	// run op command
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("error running `op item get %s --vault %s`: %v; stderr: %s", title, vault, err, stderr.String())
	}

	var item Item
	if err := json.Unmarshal(out.Bytes(), &item); err != nil {
		return nil, fmt.Errorf("error unmarshalling item: %v", err)
	}

	return &item, nil
}

// CreateItem creates an item in 1password
func (c *cli) CreateItem(item *Item) error {

	// op cli needs the --category argument to work: Login, Password, Server, etc.,
	// However, MUST be omitted from template/json in that case.
	// Handling here so that nothing needs to be remembered when createing items.
	category := item.Category
	item.Category = "" // --> becomes omitempty in the marshalled json object below.

	// marshal 1password item to json
	itemJson, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal item: %v", err)
	}

	// prepare 1password command
	// --template= needs a real file path to a template file.
	// "-" lets you pass in standard input: see https://developer.1password.com/docs/cli/reference/management-commands/item#create-an-item-using-a-json-template
	cmd := exec.Command("op", "item", "create", "--category", category, "-")
	cmd.Stdin = strings.NewReader(string(itemJson))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running `op item create --category %s - <item json>`: %v; output: %s", category, err, output)
	}

	c.logger.Info(fmt.Sprintf("1password item created: %s", item.Title))

	return nil
}

// EditItem edits an item in 1password
func (c *cli) EditItem(item *Item) error {

	// marshal edited 1password item to json
	itemJson, err := json.Marshal(item)
	if err != nil {
		return fmt.Errorf("failed to marshal item: %v", err)
	}

	// prepare 1password command
	// --template= needs a file path to a template file.
	// "-" lets you pass in standard input: see https://developer.1password.com/docs/cli/reference/management-commands/item#create-an-item-using-a-json-template
	cmd := exec.Command("op", "item", "edit", item.Title, "-")
	cmd.Stdin = strings.NewReader(string(itemJson))

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("error running `op item edit `: %v; output: %s", err, output)
	}

	c.logger.Info(fmt.Sprintf("1password item edited: %s", item.Title))

	return nil
}

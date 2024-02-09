package data

type Indexer interface {
	ObtainBlindIndex(string) (string, error)
}

type HmacIndexer struct {
	Secret string
}

func (i *HmacIndexer) ObtainBlindIndex(string) (string, error) {

}

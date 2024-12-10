package onepassword

// Vault is a model for the json output of the vault object from the 1password cli
type Vault struct {
	Id   string `json:"id"`
	Name string `json:"name"`
}

// Item is a model for the json output of the item object from the 1password cli
type Item struct {
	Id             string   `json:"id"`
	Title          string   `json:"title"`
	Tags           []string `json:"tags"`
	Version        int      `json:"version"`
	Vault          Vault    `json:"vault"`
	Category       string   `json:"category"`
	LastEditedBy   string   `json:"last_edited_by"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
	AdditionalInfo string   `json:"additional_information"`
	Urls           []Url    `json:"urls"`
	Fields         []Field  `json:"fields"`
	Files          []File   `json:"files"`
}

// Url is a model for the json output of the url object from the 1password cli
type Url struct {
	Label   string `json:"label"`
	Primary bool   `json:"primary"`
	Href    string `json:"href"`
}

// Field is a model for the json output of the fields object from the 1password cli
type Field struct {
	Id              string          `json:"id"`
	Type            string          `json:"type"`
	Purpose         string          `json:"purpose"`
	Label           string          `json:"label"`
	Value           string          `json:"value"`
	Reference       string          `json:"reference"`
	PasswordDetails PasswordDetails `json:"password_details"`
}

// PasswordDetails is a model for the json output of the password_details object from the 1password cli
type PasswordDetails struct {
	Strength string `json:"strength"`
}

// File is a model for the json output of the files object from the 1password cli
type File struct {
	Id          string `json:"id"`
	Name        string `json:"name"`
	Size        int    `json:"size"`
	ContentPath string `json:"content_path"`
}

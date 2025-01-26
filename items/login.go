package items

type Login struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	Websites []string `json:"websites"`
	Tags     []string `json:"tags"`
	ItemName string   `json:"item_name"`
}
